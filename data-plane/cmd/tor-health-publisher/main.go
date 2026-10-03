// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// This fixed publisher is part of Tor's route TCB, with Tor's native authority.
// It has no CP/observer inputs or listener (Constitution II/III; T203).
package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"github.com/zcat-app/stargate/data-plane/internal/torhealth"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	readyReply    = "READY/1\n"
	notReadyReply = "NOT_READY/1\n"
	unavailable   = "UNAVAILABLE/1\n"
	torWindow     = 4 * time.Second
	maxReplyBytes = 8 * 1024
	maxReplyLines = 64
	maxLineBytes  = 8 * 1024
)

type config struct{ torSocket, cookiePath string }

func main() {
	fd, err := unix.Open(os.DevNull, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		os.Exit(1)
	}
	if unix.Dup2(fd, 1) != nil || unix.Dup2(fd, 2) != nil {
		os.Exit(1)
	}
	if fd > 2 {
		_ = unix.Close(fd)
	}
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	c := config{torSocket: "/var/lib/tor/control/tor-control.sock", cookiePath: "/var/lib/tor/control_auth_cookie"}
	_ = torhealth.Write(torhealth.Directory, torhealth.Unavailable, torhealth.Stamp{})
	query := newQueryReader(readCookie)
	runPublisher(context.Background(), func() { publish(c, query) })
}
func runPublisher(ctx context.Context, attempt func()) {
	for ctx.Err() == nil {
		attempt()
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func publish(c config, query func(config) string) {
	start, err := torhealth.Now()
	state := torhealth.Unavailable
	if err == nil {
		reply := query(c)
		end, clockErr := torhealth.Now()
		if clockErr == nil && end.Domain == start.Domain && end.Boot >= start.Boot && end.Boot-start.Boot < int64(torhealth.Window) {
			switch reply {
			case readyReply:
				state = torhealth.Ready
			case notReadyReply:
				state = torhealth.NotReady
			}
		}
	}
	_ = torhealth.Write(torhealth.Directory, state, start)
}
func readCookie(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "cookie")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != 32 {
		return nil, errors.New("invalid cookie")
	}
	var b [33]byte
	n, err := io.ReadFull(f, b[:])
	if n != 32 || err != io.ErrUnexpectedEOF {
		return nil, errors.New("invalid cookie")
	}
	return b[:32], nil
}
func torHealth(c config) string { return torHealthWithReader(context.Background(), c, readCookie) }

// One coordinator owns one worker slot. Filesystem calls cannot be canceled by
// a Go context: on deadline the observation becomes unavailable, the socket
// context is canceled, and the slot remains occupied until the worker returns.
// Late results never publish and no replacement worker can accumulate behind a
// stalled regular-file read. The independent launcher can terminate this process.
func newQueryReader(read func(string) ([]byte, error)) func(config) string {
	var pending <-chan string
	return func(c config) string {
		if pending != nil {
			select {
			case <-pending:
				pending = nil
			default:
				return unavailable
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), torWindow)
		defer cancel()
		done := make(chan string, 1)
		pending = done
		go func() { done <- torHealthWithReader(ctx, c, read) }()
		select {
		case result := <-done:
			pending = nil
			if ctx.Err() != nil {
				return unavailable
			}
			return result
		case <-ctx.Done():
			return unavailable
		}
	}
}
func torHealthWithReader(parent context.Context, c config, read func(string) ([]byte, error)) string {
	ctx, cancel := context.WithTimeout(parent, torWindow)
	defer cancel()
	cookie, err := read(c.cookiePath)
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
			return "", errors.New("tor reply too large")
		}
		line = append(line, one[0])
		if len(line) > maxLineBytes {
			return "", errors.New("tor line too large")
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
