// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package tor hosts the runtime contract tests for the Tor sidecar's
// network-exposure invariants (see port_exposure_test.go for the package
// doc). This file is the cookie-authenticated control-port client named by
// spec.md §FR-016 (T062): the helper every US2 circuit-isolation assertion
// reads circuit state through — T058/T058a contract tests, T059–T061
// integration tests, and T070a's no-retry proof.
//
// Wire protocol: the production client SidecarMonitor.java (control-plane,
// T039/T094a) is the precedent — AUTHENTICATE carries the lowercase hex of
// the raw cookie bytes, replies are CRLF-terminated lines shaped
// `<3-digit status><sep><payload>` with sep ' ' (final), '-' (continuation)
// or '+' (dot-stuffed data block), and the session ends with QUIT.
//
// Transport (FR-012): raw control is a private Unix socket inside Tor.
// The session therefore terminates INSIDE the tor container via
// `docker compose exec -T tor nc -U /var/lib/tor/control/tor-control.sock`;
// the Go side owns the
// protocol (cookie handling, framing, reply parsing) and drives it through
// the exec pipes. `docker compose exec` runs as the image's USER tor — the
// 0640 tor:tor cookie's owner — which is why ReadCookie can read what the
// T032 shell probe read. This is the "Go-side TCP+cookie client" the
// live_sidecar_test.go (T032) header promised.
//
// Cadence: this is library code (no build tag) so both consumer modules can
// import it; it requires docker at RUNTIME. Its tests split accordingly —
// control_port_test.go (untagged, hermetic, PR gate) pins the parser and
// error discipline; control_port_live_test.go (//go:build docker) pins the
// live AUTHENTICATE → GETINFO → circuit-status path against the production
// tor image.
package tor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/zcat-app/stargate/tests/contract/internal/compose"
)

// CookieAuthPath is the authoritative control-cookie path inside the tor
// container — contracts/torrc.md invariant #11 (T087 pinned
// `DataDirectory /var/lib/tor` so the cookie lands HERE, not at
// /var/lib/tor/.tor/..., the compile-time default the entrypoint falls back
// to when torrc-defaults is not loaded). Reading the wrong path is the exact
// regression T087 fixed; ReadCookie fails loudly rather than guessing.
const CookieAuthPath = "/var/lib/tor/control_auth_cookie"

const ControlSocketPath = "/var/lib/tor/control/tor-control.sock"

// Bounds for the external-input side of the protocol (validate at the edge;
// tor's control protocol publishes no reply-size contract). Generous enough
// that GETINFO circuit-status for T061's 100-circuit run (~tens of KiB)
// parses whole; tight enough that a runaway peer cannot balloon memory.
const (
	maxCookieBytes = 4 << 10  // the real cookie is 32 bytes; more means the wrong file
	maxLineBytes   = 64 << 10 // one reply line / one data-block line
	maxReplyLines  = 1 << 14  // reply lines incl. data-block lines
	maxReplyBytes  = 8 << 20  // total payload bytes per reply
)

// ControlPortConfig locates the compose project the tor sidecar runs in —
// the same invocation context every live suite in this repo already threads
// (T019b/T032 conventions: namespaced project, explicit compose + env file).
// Zero-value is invalid; validate runs on every use.
type ControlPortConfig struct {
	Project     string // compose -p
	ComposeFile string // -f (absolute path)
	EnvFile     string // --env-file (absolute path)
}

func (c ControlPortConfig) validate() error {
	for name, val := range map[string]string{
		"Project": c.Project, "ComposeFile": c.ComposeFile, "EnvFile": c.EnvFile,
	} {
		if val == "" {
			return fmt.Errorf("ControlPortConfig.%s is empty", name)
		}
	}
	return nil
}

// composeArgs builds the shared `docker compose -p … -f … --env-file …`
// prefix by delegating to the T121 helper (internal/compose.Args, pinned
// by its compose_test.go) — the one argv builder every tests/contract
// suite now shares.
func composeArgs(cfg ControlPortConfig, args ...string) []string {
	return compose.Args(cfg.Project, cfg.ComposeFile, cfg.EnvFile, args...)
}

// ReadCookie reads the raw control-auth cookie bytes out of the tor
// container. Byte-safe: `exec -T` keeps stdout a pipe (no TTY mangling) and
// the cookie may contain ANY bytes — hex encoding happens at Authenticate,
// never on disk or in logs. Failure messages carry sizes and paths, never
// cookie bytes (T062 §Analysis M5 — harness plumbing must not become the
// leak the feature exists to prevent).
func ReadCookie(ctx context.Context, cfg ControlPortConfig) ([]byte, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "docker", composeArgs(cfg,
		"exec", "-T", "tor", "cat", CookieAuthPath)...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("read control cookie (docker compose exec tor cat %s failed): %w: %s",
			CookieAuthPath, err, strings.TrimSpace(errOut.String()))
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("control cookie at %s is empty (tor not finished writing it, or wrong DataDirectory — invariant #11)", CookieAuthPath)
	}
	if out.Len() > maxCookieBytes {
		return nil, fmt.Errorf("control cookie read at %s is %d bytes (expected ~32) — not a cookie file", CookieAuthPath, out.Len())
	}
	return out.Bytes(), nil
}

// ControlPort is one authenticated-or-not control-port session through the
// in-container nc transport. Sequential, single-goroutine: each Command
// writes one request then reads its full reply (interleaved, never
// dump-then-read — a >pipe-buffer reply such as T061's 100-circuit
// circuit-status would deadlock a write-everything-first caller; T062
// §Analysis M3). Not safe for concurrent use.
type ControlPort struct {
	w      *bufio.Writer  // command sink (the exec stdin when live)
	r      *bufio.Reader  // reply source (the exec stdout when live)
	stdin  io.WriteCloser // non-nil live: closed by Close
	cmd    *exec.Cmd      // non-nil live: waited/killed by Close
	stderr *bytes.Buffer  // non-nil live: nc/docker diagnostics for Close errors
}

// Connect opens a control-port session: it spawns
// `docker compose exec -T tor nc -U /var/lib/tor/control/tor-control.sock` and wires the protocol
// pipes. The tor service must already be running in the cfg project (every
// consumer brings the stack up first). nc dying early (control port not yet
// listening) surfaces on first use — as an EOF-shaped error from
// Authenticate/Command — not here; poll at the caller (the live self-test's
// bootstrap poll is the reference shape). Cancel ctx to tear the session
// down from the outside.
func Connect(ctx context.Context, cfg ControlPortConfig) (*ControlPort, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "docker", composeArgs(cfg,
		"exec", "-T", "tor", "nc", "-U", ControlSocketPath)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("control session stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("control session stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("control session start (docker compose exec tor nc -U %s): %w: %s",
			ControlSocketPath, err, strings.TrimSpace(stderr.String()))
	}
	return &ControlPort{
		w:      bufio.NewWriter(stdin),
		r:      bufio.NewReader(stdout),
		stdin:  stdin,
		cmd:    cmd,
		stderr: &stderr,
	}, nil
}

// Authenticate sends the COOKIE-method handshake: `AUTHENTICATE <hex>` with
// the lowercase hex of the raw cookie bytes (SidecarMonitor wire shape). On
// success the session is authenticated and subsequent Commands run under
// the cookie's authority. On failure the session is dead (tor rejects and
// typically closes) — reconnect rather than retry.
func (p *ControlPort) Authenticate(cookie []byte) error {
	if len(cookie) == 0 {
		return errors.New("authenticate: empty cookie")
	}
	// The command string embeds the cookie; roundTrip's errors never echo
	// the command (M5), so the hex cannot leak through the error path.
	if _, err := p.Command("AUTHENTICATE " + hex.EncodeToString(cookie)); err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	return nil
}

// Command sends one control command and returns the reply's payload lines:
// continuation (`250-`) and final (`250 `) payloads in order, plus any
// data-block (`250+`) lines with dot-stuffing removed. A `250 OK` reply
// therefore yields ["OK"]. Non-2xx statuses and protocol violations are
// errors carrying the status line — never the command text, so the
// AUTHENTICATE hex cannot leak into messages through this path (M5).
//
// After ANY error, discard the ControlPort (Close it and Connect anew) —
// a reply aborted mid-parse leaves unparsed bytes in the stream, so
// retrying on the same session would parse a previous reply's tail as the
// next response. The same discard-after-error rule is what makes the
// interleaved write→read pairing in Command safe to document: a fresh
// session always starts at a clean reply boundary.
func (p *ControlPort) Command(command string) ([]string, error) {
	if strings.ContainsAny(command, "\r\n") {
		return nil, errors.New("control command contains a line break")
	}
	if _, err := p.w.WriteString(command + "\r\n"); err != nil {
		return nil, fmt.Errorf("control write: %w", err)
	}
	if err := p.w.Flush(); err != nil {
		return nil, fmt.Errorf("control write: %w", err)
	}
	return p.readReply()
}

// Close ends the session: QUIT (best-effort — tor replies "250 closing
// connection" and closes), then stdin close and process wait. A live
// process still running after the grace kill-window is terminated; the
// wait error is returned so a broken transport surfaces at the caller.
func (p *ControlPort) Close() error {
	if p == nil {
		return nil
	}
	if p.w != nil {
		// Best-effort QUIT; the reply (if any) is never parsed — nc exits
		// when tor closes the socket.
		_, _ = p.w.WriteString("QUIT\r\n")
		_ = p.w.Flush()
	}
	var waitErr error
	if p.cmd != nil && p.cmd.Process != nil {
		// Wait blocks until nc exits; exec.CommandContext's deadline (the
		// caller's ctx) is the backstop, but do not rely on it alone —
		// Close is also the deferred-cleanup path for tests that bound
		// their ctx on the happy path only.
		done := make(chan error, 1)
		go func() { done <- p.cmd.Wait() }()
		select {
		case waitErr = <-done:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			waitErr = <-done
		}
	} else if p.stdin != nil {
		_ = p.stdin.Close()
	}
	if waitErr != nil {
		waitErr = fmt.Errorf("control session close: %w: %s",
			waitErr, strings.TrimSpace(p.stderrString()))
	}
	return waitErr
}

func (p *ControlPort) stderrString() string {
	if p.stderr == nil {
		return ""
	}
	return p.stderr.String()
}

// readReply reads one complete reply (through data blocks to the final
// `2xx ` line) and returns its payload lines. Bounded per maxLineBytes /
// maxReplyLines / maxReplyBytes — the reply is external input.
func (p *ControlPort) readReply() ([]string, error) {
	var (
		payloads []string
		total    int
	)
	for lineNo := 0; ; lineNo++ {
		if lineNo >= maxReplyLines {
			return nil, fmt.Errorf("control reply exceeded %d lines", maxReplyLines)
		}
		line, err := p.readLine()
		if err != nil {
			return nil, err
		}
		total += len(line)
		if total > maxReplyBytes {
			return nil, fmt.Errorf("control reply exceeded %d bytes", maxReplyBytes)
		}
		if len(line) < 4 {
			return nil, fmt.Errorf("malformed control reply line (too short): %q", truncate(line))
		}
		status, sep, payload := line[:3], line[3], line[4:]
		if !isDigits(status) {
			return nil, fmt.Errorf("malformed control reply status: %q", truncate(line))
		}
		if status[0] != '2' {
			return nil, fmt.Errorf("control reply status %s: %s", status, payload)
		}
		switch sep {
		case ' ':
			return append(payloads, payload), nil
		case '-':
			payloads = append(payloads, payload)
		case '+':
			block, err := p.readDataBlock(&total)
			if err != nil {
				return nil, err
			}
			payloads = append(payloads, payload)
			payloads = append(payloads, block...)
		default:
			return nil, fmt.Errorf("malformed control reply separator %q in: %q", string(sep), truncate(line))
		}
	}
}

// readDataBlock reads a `250+` data block's body: raw lines until a lone
// "." (control-spec §2.3 dot-termination), un-stuffing the leading-dot
// escape (".." → ".") tor applies to data lines that begin with a period.
func (p *ControlPort) readDataBlock(total *int) ([]string, error) {
	var block []string
	for lineNo := 0; ; lineNo++ {
		if lineNo >= maxReplyLines {
			return nil, fmt.Errorf("control data block exceeded %d lines", maxReplyLines)
		}
		line, err := p.readLine()
		if err != nil {
			return nil, err
		}
		*total += len(line)
		if *total > maxReplyBytes {
			return nil, fmt.Errorf("control reply exceeded %d bytes", maxReplyBytes)
		}
		if line == "." {
			return block, nil
		}
		if strings.HasPrefix(line, ".") {
			line = line[1:] // dot-stuffing: ".." was a literal "."
		}
		block = append(block, line)
	}
}

// readLine reads one CRLF-terminated line, bounded by maxLineBytes. On EOF
// the nc/docker stderr (if any) is attached — a dead transport (nc died on
// a bad target, exec teardown, container exit) presents as EOF, and the
// diagnostics name which. stderr carries nc/docker errors only, never
// protocol traffic (M5).
func (p *ControlPort) readLine() (string, error) {
	var sb strings.Builder
	for {
		b, err := p.r.ReadByte()
		if err != nil {
			if diag := strings.TrimSpace(p.stderrString()); diag != "" {
				return "", fmt.Errorf("control port closed mid-reply: %w (transport diagnostics: %s)", err, diag)
			}
			return "", fmt.Errorf("control port closed mid-reply: %w", err)
		}
		if b == '\n' {
			line := sb.String()
			return strings.TrimSuffix(line, "\r"), nil
		}
		sb.WriteByte(b)
		if sb.Len() > maxLineBytes {
			return "", fmt.Errorf("control reply line exceeded %d bytes", maxLineBytes)
		}
	}
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// truncate bounds a malformed line inside an error message (M4/M5 hygiene:
// diagnostics are bounded and never echo commands).
func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}
