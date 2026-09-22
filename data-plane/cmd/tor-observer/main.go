// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// The observer is the only Stargate process with Tor control authority.
// Constitution II/III and foundation-boundaries.md permit this process to
// reduce one fixed Tor bootstrap query to a finite health token; it has no
// command-bearing CP input and no IP network namespace in production.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	healthRequest = "HEALTH/1\n"
	readyReply    = "READY/1\n"
	notReadyReply = "NOT_READY/1\n"
	unavailable   = "UNAVAILABLE/1\n"
	authWindow    = time.Second
	requestWindow = time.Second
	torWindow     = 4 * time.Second
	maxReplyBytes = 8 * 1024
	maxReplyLines = 64
	maxLineBytes  = 8 * 1024
	maxHandshakes = 16
)

type config struct {
	healthSocket string
	torSocket    string
	cookiePath   string
	privateKey   string
	peerKey      string
}

func main() {
	// Constitution III: suppress dependency/runtime output before processing private state.
	fd, err := unix.Open(os.DevNull, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		os.Exit(1)
	}
	if unix.Dup2(fd, 1) != nil || unix.Dup2(fd, 2) != nil {
		os.Exit(1)
	}
	// A launcher may have closed a standard descriptor; keep the replacement
	// open in that case so later private files cannot occupy stdout/stderr.
	if fd > 2 {
		_ = unix.Close(fd)
	}

	c := config{
		healthSocket: "/run/stargate-tor-observer/health.sock",
		torSocket:    "/run/tor-control/tor-control.sock",
		cookiePath:   "/run/tor-control/control_auth_cookie",
		privateKey:   "/etc/stargate/observer-keys/observer.priv",
		peerKey:      "/etc/stargate/observer-keys/cp.pub",
	}
	os.Exit(run(c, os.Args[1:]))
}

// Only the invoking operator can select the fixed one-shot readiness mode.
// It executes inside the observer's existing authority, exposes no raw reply,
// and inherits torHealth's four-second deadline (Constitution III / T152).
func run(c config, args []string) int {
	if len(args) == 1 && args[0] == "--check-ready" {
		// File I/O can block independently of the socket deadline. A one-shot
		// process must still exit; the buffered result cannot strand its sender.
		sample := make(chan string, 1)
		go func() { sample <- torHealth(c) }()
		var current string
		select {
		case current = <-sample:
		case <-time.After(torWindow):
			return 2
		}
		switch current {
		case readyReply:
			return 0
		case notReadyReply:
			return 1
		default:
			return 2
		}
	}
	if len(args) != 0 {
		return 2
	}
	if err := serve(context.Background(), c, nil); err != nil {
		// The service's startup failure is intentionally static: an arbitrary
		// path or upstream error must not become a diagnostic detail stream.
		return 2
	}
	return 0
}

// serve accepts authenticated, one-shot requests. The ready channel is a
// test seam; production has no readiness claim beyond a bound socket.
func serve(ctx context.Context, c config, ready chan<- struct{}) error {
	priv, err := readPrivateKey(c.privateKey)
	if err != nil {
		return err
	}
	if _, err := readPublicKey(c.peerKey); err != nil {
		return err
	}
	if info, err := os.Lstat(c.healthSocket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("health path is not a socket")
		}
		if err := os.Remove(c.healthSocket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	l, err := net.Listen("unix", c.healthSocket)
	if err != nil {
		return err
	}
	defer l.Close()
	defer os.Remove(c.healthSocket)
	if err := os.Chmod(c.healthSocket, 0660); err != nil {
		return err
	}
	if ready != nil {
		close(ready)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	queries := make(chan struct{}, 1)
	handshakes := make(chan struct{}, maxHandshakes)
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case handshakes <- struct{}{}:
			go func() {
				defer func() { <-handshakes }()
				handle(conn, c, priv, queries)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func handle(conn net.Conn, c config, priv ed25519.PrivateKey, queries chan struct{}) {
	defer conn.Close()
	if err := authenticate(conn, c.peerKey, priv); err != nil {
		return // invalid callers receive no token and cause no Tor query
	}
	_ = conn.SetDeadline(time.Now().Add(requestWindow))
	var req [len(healthRequest)]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil || string(req[:]) != healthRequest {
		return
	}
	var extra [1]byte
	if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF {
		return // exact framing includes the client write-EOF
	}
	select {
	case queries <- struct{}{}:
		defer func() { <-queries }()
	default:
		_, _ = io.WriteString(conn, unavailable)
		return
	}
	// The Tor budget starts after validated request EOF; no unauthenticated
	// input is permitted to hold a query slot or reach the control socket.
	result := torHealth(c)
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(conn, result)
}

func authenticate(conn net.Conn, peerPath string, priv ed25519.PrivateKey) error {
	_ = conn.SetDeadline(time.Now().Add(authWindow))
	var serverNonce [32]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		return err
	}
	if _, err := conn.Write(append([]byte("OBS/1\n"), serverNonce[:]...)); err != nil {
		return err
	}
	var client [5 + 32 + ed25519.SignatureSize]byte
	if _, err := io.ReadFull(conn, client[:]); err != nil || string(client[:5]) != "CP/1\n" {
		return errors.New("invalid caller")
	}
	peer, err := readPublicKey(peerPath) // current authorized pin on each call
	if err != nil {
		return err
	}
	transcript := append(append([]byte{}, serverNonce[:]...), client[5:37]...)
	message := append([]byte("stargate-observer/1 client\n"), transcript...)
	if !ed25519.Verify(peer, message, client[37:]) {
		return errors.New("invalid caller")
	}
	proof := ed25519.Sign(priv, append([]byte("stargate-observer/1 server\n"), transcript...))
	_, err = conn.Write(append([]byte("OK/1\n"), proof...))
	return err
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return key, nil
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return key, nil
}

func torHealth(c config) string {
	ctx, cancel := context.WithTimeout(context.Background(), torWindow)
	defer cancel()
	cookie, err := os.ReadFile(c.cookiePath)
	if err != nil || len(cookie) != 32 {
		return unavailable
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.torSocket)
	if err != nil {
		return unavailable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Until(deadline(ctx))))
	defer func() { _, _ = io.WriteString(conn, "QUIT\r\n") }()
	if _, err := io.WriteString(conn, "AUTHENTICATE "+hex.EncodeToString(cookie)+"\r\n"); err != nil {
		return unavailable
	}
	budget := &replyBudget{}
	auth, err := readTorLine(conn, budget)
	if err != nil || auth != "250 OK" {
		return unavailable
	}
	if _, err := io.WriteString(conn, "GETINFO status/bootstrap-phase\r\n"); err != nil {
		return unavailable
	}
	progress, err := readBootstrap(conn, budget)
	if err != nil {
		return unavailable
	}
	if progress == 100 {
		return readyReply
	}
	return notReadyReply
}

func deadline(ctx context.Context) time.Time {
	d, _ := ctx.Deadline()
	return d
}

type replyBudget struct {
	bytes int
	lines int
}

func readTorLine(r io.Reader, budget *replyBudget) (string, error) {
	var line []byte
	var one [1]byte
	for {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return "", err
		}
		budget.bytes++
		if budget.bytes > maxReplyBytes {
			return "", errors.New("Tor reply too large")
		}
		line = append(line, one[0])
		if len(line) > maxLineBytes {
			return "", errors.New("Tor line too large")
		}
		if one[0] == '\n' {
			budget.lines++
			if budget.lines > maxReplyLines || len(line) < 2 || line[len(line)-2] != '\r' {
				return "", errors.New("invalid Tor line")
			}
			return string(line[:len(line)-2]), nil
		}
	}
}

func readBootstrap(conn net.Conn, budget *replyBudget) (int, error) {
	line, err := readTorLine(conn, budget)
	if err != nil || !strings.HasPrefix(line, "250-status/bootstrap-phase=") {
		return 0, errors.New("invalid Tor bootstrap reply")
	}
	phase := strings.TrimPrefix(line, "250-status/bootstrap-phase=")
	// Tor's GETINFO value is a STATUS_CLIENT bootstrap event without its
	// "650 STATUS_CLIENT" envelope. Require its mandatory structure before
	// reducing PROGRESS, so arbitrary text containing PROGRESS=100 cannot
	// produce READY. Unknown fields remain permitted by the control spec.
	// https://spec.torproject.org/control-spec/commands.html#GETINFO
	// https://spec.torproject.org/control-spec/replies.html#status-events
	var arguments string
	if strings.HasPrefix(phase, "NOTICE BOOTSTRAP ") {
		arguments = strings.TrimPrefix(phase, "NOTICE BOOTSTRAP ")
	} else if strings.HasPrefix(phase, "WARN BOOTSTRAP ") {
		arguments = strings.TrimPrefix(phase, "WARN BOOTSTRAP ")
	} else {
		return 0, errors.New("invalid Tor bootstrap event")
	}
	fields, err := parseBootstrapFields(arguments)
	if err != nil || fields["TAG"] == "" || fields["SUMMARY"] == "" {
		return 0, errors.New("invalid Tor bootstrap fields")
	}
	progress, err := strconv.Atoi(fields["PROGRESS"])
	if err != nil || progress < 0 || progress > 100 {
		return 0, errors.New("invalid progress")
	}
	end, err := readTorLine(conn, budget)
	if err != nil || subtle.ConstantTimeCompare([]byte(end), []byte("250 OK")) != 1 {
		return 0, errors.New("invalid Tor completion")
	}
	return progress, nil
}

func parseBootstrapFields(input string) (map[string]string, error) {
	fields := make(map[string]string)
	for len(input) > 0 {
		equal := strings.IndexByte(input, '=')
		if equal <= 0 || strings.IndexByte(input[:equal], ' ') >= 0 {
			return nil, errors.New("invalid Tor field")
		}
		key := input[:equal]
		if !torKeyword(key) {
			return nil, errors.New("invalid Tor field name")
		}
		input = input[equal+1:]
		if input == "" {
			return nil, errors.New("empty Tor field")
		}
		if input[0] == '"' && (key == "PROGRESS" || key == "TAG") {
			return nil, errors.New("invalid Tor bootstrap field type")
		}
		var value string
		if input[0] == '"' {
			closing := -1
			for i := 1; i < len(input); i++ {
				if input[i] == '\\' && i+1 < len(input) {
					i++
				} else if input[i] == '"' {
					closing = i
					break
				}
			}
			if closing < 0 {
				return nil, errors.New("unterminated Tor field")
			}
			value, input = input[1:closing], input[closing+1:]
		} else {
			end := strings.IndexByte(input, ' ')
			if end < 0 {
				end = len(input)
			}
			value, input = input[:end], input[end:]
			if !torKeyword(value) {
				return nil, errors.New("invalid Tor field value")
			}
		}
		if value == "" {
			return nil, errors.New("empty Tor field value")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("duplicate Tor field")
		}
		fields[key] = value
		if input != "" {
			if input[0] != ' ' || len(input) == 1 || input[1] == ' ' {
				return nil, errors.New("invalid Tor field separator")
			}
			input = input[1:]
		}
	}
	return fields, nil
}

func torKeyword(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_') {
			return false
		}
	}
	return true
}
