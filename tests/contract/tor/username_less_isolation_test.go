//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// username_less_isolation_test.go is T058a: the contract test pinning Tor's
// IsolateSOCKSAuth behaviour when an upstream SOCKS5 client provides NO
// username — the negative companion to T058's isolate_socks_auth_effect_test.go
// (tests/contract/torrc/, a different package by FR-016's six-directory
// split). Tor's IsolateSOCKSAuth isolates only credential-BEARING streams;
// credential-less (method 0x00) connections share a circuit by design. This
// file pins that share, because the data plane's outbound contract (T047:
// always forward with the inbound first-party username) is defensive against
// exactly one failure mode — silently forwarding a username-less request and
// fusing all such users onto one circuit. If a future tor release rejects
// NO_AUTH outright or isolates credential-less streams, this test fails in
// the digest-bump PR (Principle IV manual promotion) and the outbound
// contract is renegotiated with a SECURITY-DECISIONS.md entry.
//
// Transport (FR-012): the host has no Tor TCP SOCKS port, so the SOCKS5
// sessions ride the same in-container exec/nc pattern as the T062
// control client — `docker compose exec -T tor nc -U /run/tor-fabric/private/tor-socks.sock` with
// the Go side owning the wire bytes (RFC 1928 greeting/method-selection,
// CONNECT request, reply parsing). The control side (cookie auth, circuit
// reads) is the landed T062 helper, consumed unmodified; the torrc under
// test is the image-baked golden (`SocksPort unix:/run/tor-fabric/private/tor-socks.sock IsolateClientAddr
// IsolateSOCKSAuth`), so "the rendered torrc" needs no harness rendering.
//
// Destination: the spec-pinned reference onion (T033's t033Onion —
// tests/integration/onion_load_test.go; the constant is duplicated here
// because tests/integration is a separate Go module). A synthetic
// `.example.onion` never attaches a stream — the descriptor fetch fails
// before rendezvous — so the pin needs a real, resolvable onion. Streams are
// matched by target string and counted exactly, never by StreamID ordering.
//
// Deadline model: individual SOCKS CONNECTs (descriptor fetch + rendezvous)
// are bounded only by the suite-wide context below — a hung rendezvous kills
// nc via CommandContext and surfaces as a short read. The fine-grained
// deadlines bound the polls; the suite deadline bounds everything else.
//
// stargate:cadence docker — this suite BRINGS UP the tor service and needs
// the live Tor network for bootstrap, so it is build-tagged out of the
// hermetic PR gate and runs in the named Docker job
// (`STARGATE_TEST_TAGS=docker scripts/verify.sh`), or manually:
//
//	cd tests/contract && go test -tags docker ./tor/ -run TestUsernameLessIsolation -v -timeout 20m
//
// Skip guards mirror T019b/T032/T062 (docker CLI absent / daemon
// unreachable).
package tor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zcat-app/stargate/tests/contract/internal/compose"
)

// ulComposeProject namespaces every compose invocation this suite issues so
// it never collides with operator-authored state or sibling suites
// (stargate-t019b-test, stargate-t032-test, stargate-t062-test, and T058's
// own project in tests/contract/torrc/). Pre-registered cleanup tears the
// project down regardless of which subtest failed.
const ulComposeProject = "stargate-t058a-test"

// ulOnion is the reference onion this suite CONNECTs to. Same spec-pinned
// address as T033's t033Onion (provenance above); port 80 is the address's
// documented HTTP port. Port 443 is deliberately NOT used: the pin is about
// circuit attachment, not TLS, and speaking TLS would need a client stack
// this suite must not grow.
const (
	ulOnion     = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	ulOnionPort = 80
)

const (
	ulUpDeadline   = 5 * time.Minute // compose build + start (mirrors T019b/T062)
	ulBootDeadline = 5 * time.Minute // tor bootstrap on the live network (T032's deadline)
	ulPollEvery    = 2 * time.Second // control-port poll cadence (T062's pace)
	ulConnectWait  = 3 * time.Minute // first-working-CONNECT window. Post-bootstrap
	// descriptor fetch + circuit-builder warmup can outlive PROGRESS=100
	// (T033 retries for the same transience: 90 s when this was written,
	// 390 s since T208); this was set wider than T033's then-90 s window
	// because the first pairing runs closest to boot on a possibly
	// cold volume. Honest provenance: the diagnosed live REP=1 storms were
	// the DST.ADDR wire bug (§Notes #4), NOT warmup — the headroom is
	// precautionary and costs nothing on the happy path. Only the first
	// pairing uses this; the calibration subtest runs descriptor-warm and
	// keeps ulStreamWait.
	ulStreamWait      = 90 * time.Second // stream-attach wait (the 90 s T033's retry window had before T208)
	ulDrainWait       = 30 * time.Second // wait for prior subtest's streams to detach
	ulOverallDeadline = 18 * time.Minute // whole-suite ctx (test -timeout 20m is the outer bound;
	// worst-case arithmetic: up 5m + boot 5m + connect 3m + stream 1.5m +
	// drain 0.5m + connect 1.5m + stream 1.5m ≈ 18m — the stacked-worst case
	// coincides with ctx cancel, which surfaces as a loud deadline failure,
	// not a hang)
)

// SOCKS5 wire constants (RFC 1928).
const (
	ulVer5           = 0x05
	ulMethodNoAuth   = 0x00
	ulMethodUserPass = 0x02
	ulCmdConnect     = 0x01
	ulAtypIPv4       = 0x01
	ulAtypDomain     = 0x03
	ulAtypIPv6       = 0x04
	ulRepSucceeded   = 0x00
)

func TestUsernameLessIsolation(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ulOverallDeadline)
	defer cancel()

	repoRoot := findRepoRoot(t) // same package under -tags docker (port_exposure_test.go)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}
	cfg := ControlPortConfig{Project: ulComposeProject, ComposeFile: composeFile, EnvFile: envFile}

	// Cleanup BEFORE up (T019b's ordering rationale: a partially-successful
	// up must not orphan the project when the test aborts).
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer downCancel()
		if out, err := compose.Run(downCtx, ulComposeProject, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	upCtx, upCancel := context.WithTimeout(ctx, ulUpDeadline)
	defer upCancel()
	if out, err := compose.Run(upCtx, ulComposeProject, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up -d --build tor: %v\n%s", err, out)
	}

	// Authenticated control session, polled through the startup window (the
	// T062 live self-test's bootstrap shape: cookie lands and the control
	// listener opens during startup, so first attempts may race).
	conn := ulBootstrapControl(t, ctx, cfg)
	t.Cleanup(func() { _ = conn.Close() })

	// Hold until PROGRESS=100: SOCKS CONNECT before full bootstrap fails
	// with a circuit error that would masquerade as the behaviour pin
	// failing.
	ulWaitBootstrapped(t, conn)

	// Subtests are sequential (no t.Parallel): the calibration subtest needs
	// the share subtest's streams drained first, and each subtest owns its
	// sessions outright (subtest cleanups run at SUBTEST end, so sessions
	// are never handed across subtests).
	target := fmt.Sprintf("%s:%d", ulOnion, ulOnionPort)

	// Subtest 1 — ticket assertion (a): tor accepts both NO_AUTH connections.
	t.Run("NoAuthAcceptedBothConnections", func(t *testing.T) {
		s1 := ulDialSocks(t, ctx, cfg)
		if err := s1.greetingNoAuth(); err != nil {
			t.Fatalf("SOCKS5 greeting (connection 1): %v", err)
		}
		s2 := ulDialSocks(t, ctx, cfg)
		if err := s2.greetingNoAuth(); err != nil {
			t.Fatalf("SOCKS5 greeting (connection 2): %v", err)
		}
		t.Logf("OK: tor accepted method 0x00 (NO_AUTH) on both connections")
		// No CONNECT was sent, so no stream exists; close before subtest 2
		// counts streams.
		_ = s1.close()
		_ = s2.close()
	})

	// Subtest 2 — ticket assertion (b): both credential-less streams attach
	// to the SAME circuit, and that circuit is real on tor's circuit-level
	// surface too.
	t.Run("NoAuthStreamsShareCircuit", func(t *testing.T) {
		s1, s2 := ulPairConnect(t, ctx, cfg, target,
			func(s *ulSocksSession, _ int) error { return s.greetingNoAuth() }, ulConnectWait)
		circIDs := ulWaitStreams(t, conn, target, 2, ulStreamWait)
		shared := circIDs[0]
		if shared == "0" {
			t.Fatalf("both streams reported unattached (CircID 0): %v", circIDs)
		}
		if circIDs[1] != shared {
			t.Errorf("credential-less streams attached to DIFFERENT circuits (%s vs %s) — "+
				"tor now isolates NO_AUTH streams under IsolateSOCKSAuth; T047's username-less "+
				"forwarding is no longer just latent, and the outbound contract needs a "+
				"SECURITY-DECISIONS.md renegotiation", shared, circIDs[1])
		}
		if !ulCircuitBuilt(t, conn, shared) {
			t.Errorf("shared circuit %s not found BUILT in GETINFO circuit-status — "+
				"stream-status and circuit-status disagree (reading bug or tor surface change)", shared)
		}
		t.Logf("OK: both NO_AUTH streams share circuit %s (also BUILT in circuit-status)", shared)
		// Close before the calibration subtest so its exactly-two count sees
		// only its own streams.
		_ = s1.close()
		_ = s2.close()
	})

	// Subtest 3 — positive control (external-calibration doctrine, 780aaae):
	// prove the reading machinery DETECTS isolation by exercising the
	// behaviour the torrc contract's isolate_socks_auth_effect_test.go
	// specifies (T058's surface): two distinct usernames must land on
	// distinct circuits. If this control fails, the environment cannot
	// distinguish shared from isolated, and the share assertion above is
	// unproven rather than green.
	t.Run("CalibrationDistinctUsernamesDiverge", func(t *testing.T) {
		// Drain: the previous subtest's streams must be gone before we
		// count exactly two again (tor may linger a closed stream briefly).
		ulWaitStreams(t, conn, target, 0, ulDrainWait)

		s3, s4 := ulPairConnect(t, ctx, cfg, target,
			func(s *ulSocksSession, i int) error {
				if i == 0 {
					return s.greetingUserPass("t058a-alpha")
				}
				return s.greetingUserPass("t058a-beta")
			}, ulStreamWait)
		circIDs := ulWaitStreams(t, conn, target, 2, ulStreamWait)
		if circIDs[0] == "0" || circIDs[1] == "0" {
			t.Fatalf("calibration streams unattached (CircID 0): %v", circIDs)
		}
		if circIDs[0] == circIDs[1] {
			t.Errorf("DISTINCT usernames shared circuit %s — tor no longer isolates "+
				"credential-bearing streams; the T058 isolation contract and FR-002's "+
				"per-first-party isolation are broken at the source", circIDs[0])
		}
		t.Logf("OK: distinct usernames on distinct circuits (%s vs %s) — detection machinery calibrated",
			circIDs[0], circIDs[1])
		_ = s3.close()
		_ = s4.close()
	})
}

// ulPairConnect dials and greets two fresh SOCKS sessions, CONNECTs both to
// target, and returns the live sessions. Each attempt is a full fresh
// dial+greet+connect pair; on any per-attempt failure both sessions are
// closed and the attempt is retried until the wait deadline, because an
// onion CONNECT right after PROGRESS=100 fails transiently while tor
// fetches descriptors and warms its circuit builder (T033's retry-window
// precedent; observed live as REP=1 within seconds of bootstrap). greet
// selects the credential per connection (index 0/1) — that is the whole
// variable under test. A genuine pin regression (tor rejects the method,
// isolates the class) fails every attempt identically and the deadline
// Fatal carries the last error verbatim.
func ulPairConnect(t *testing.T, ctx context.Context, cfg ControlPortConfig, target string,
	greet func(s *ulSocksSession, idx int) error, wait time.Duration) (s1, s2 *ulSocksSession) {
	t.Helper()
	deadline := time.Now().Add(wait)
	var lastErr error
	for {
		if time.Now().After(deadline) {
			t.Fatalf("no working SOCKS5 connection pair to %s within %s: %v (tor notice log tail: %s)",
				target, wait, lastErr, ulTorLogTail(t, ctx, cfg))
		}
		lastErr = nil
		s1, s2 = ulDialSocks(t, ctx, cfg), ulDialSocks(t, ctx, cfg)
		for idx, s := range []*ulSocksSession{s1, s2} {
			if err := greet(s, idx); err != nil && lastErr == nil {
				lastErr = fmt.Errorf("greeting (connection %d): %w", idx+1, err)
			}
		}
		if lastErr == nil {
			for idx, s := range []*ulSocksSession{s1, s2} {
				if err := s.connect(ulOnion); err != nil && lastErr == nil {
					lastErr = fmt.Errorf("CONNECT (connection %d): %w", idx+1, err)
				}
			}
		}
		if lastErr == nil {
			return s1, s2
		}
		_ = s1.close()
		_ = s2.close()
		time.Sleep(ulPollEvery)
	}
}

// ulTorLogTail returns the last 15 notice lines from the tor container for
// failure forensics. Safe to print: the torrc bakes `Log notice stdout` +
// `SafeLogging 1` (torrc contract invariants #8–#9 — the same channel the
// healthcheck and operators read), so addresses are scrubbed at the source.
func ulTorLogTail(t *testing.T, ctx context.Context, cfg ControlPortConfig) string {
	t.Helper()
	out, err := compose.Run(ctx, cfg.Project, cfg.ComposeFile, cfg.EnvFile, "logs", "--tail", "15", "tor")
	if err != nil {
		return fmt.Sprintf("(logs unavailable: %v)", err)
	}
	return "\n" + string(out)
}

// ulBootstrapControl polls ReadCookie + Connect + Authenticate until tor is
// accepting control sessions (T062's live bootstrap shape).
func ulBootstrapControl(t *testing.T, ctx context.Context, cfg ControlPortConfig) *ControlPort {
	t.Helper()
	deadline := time.Now().Add(ulBootDeadline)
	var lastErr error
	for {
		if time.Now().After(deadline) {
			t.Fatalf("no authenticated control session within %s: %v", ulBootDeadline, lastErr)
		}
		var err error
		var c *ControlPort
		cookie, cookieErr := ReadCookie(ctx, cfg)
		if cookieErr == nil {
			c, err = Connect(ctx, cfg)
			if err == nil {
				err = c.Authenticate(cookie)
				if err == nil {
					return c
				}
			}
		} else {
			err = cookieErr
		}
		if c != nil {
			_ = c.Close()
		}
		lastErr = err
		time.Sleep(ulPollEvery)
	}
}

// ulWaitBootstrapped polls GETINFO status/bootstrap-phase until PROGRESS=100
// (the T062 shape; the SOCKS service is only useful after full bootstrap).
func ulWaitBootstrapped(t *testing.T, conn *ControlPort) {
	t.Helper()
	deadline := time.Now().Add(ulBootDeadline)
	var last string
	for {
		lines, err := conn.Command("GETINFO status/bootstrap-phase")
		if err != nil {
			t.Fatalf("GETINFO status/bootstrap-phase mid-poll: %v (last: %s)", err, last)
		}
		last = strings.Join(lines, " | ")
		if strings.Contains(last, "PROGRESS=100") {
			t.Logf("OK: tor bootstrapped: %s", truncate(last))
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tor did not reach PROGRESS=100 within %s; last phase: %s", ulBootDeadline, truncate(last))
		}
		time.Sleep(ulPollEvery)
	}
}

// ulSocksSession is one SOCKS5 connection to the tor SocksPort over the
// in-container exec/nc transport — the private Unix SOCKS socket
// with the Go side owning the RFC 1928 wire bytes. Sequential,
// single-goroutine: each step writes then reads its bounded reply.
type ulSocksSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	r      *bufio.Reader
	stderr *bytes.Buffer
}

// ulDialSocks opens the exec/nc session to Tor's private Unix SOCKS socket
// container. Failures name the transport; the SOCKS dialogue itself starts
// only after Start succeeds. The session lives until close or until ctx is
// cancelled (CommandContext backstop).
func ulDialSocks(t *testing.T, ctx context.Context, cfg ControlPortConfig) *ulSocksSession {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", composeArgs(cfg,
		"exec", "-T", "tor", "nc", "-U", "/run/tor-fabric/private/tor-socks.sock")...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("socks session stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("socks session stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("socks session start (docker compose exec tor nc -U private SOCKS): %v: %s",
			err, strings.TrimSpace(stderr.String()))
	}
	s := &ulSocksSession{cmd: cmd, stdin: stdin, r: bufio.NewReader(stdout), stderr: &stderr}
	t.Cleanup(func() { _ = s.close() })
	return s
}

// readFull reads exactly n bytes with the transport diagnostics attached on
// short read (a dead nc presents as EOF here). Every n is a small fixed or
// length-capped size, so no runaway-read surface exists.
func (s *ulSocksSession) readFull(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, fmt.Errorf("socks reply short read (want %d bytes): %w: %s",
			n, err, strings.TrimSpace(s.stderr.String()))
	}
	return buf, nil
}

// greetingNoAuth performs the RFC 1928 method negotiation with method 0x00
// only. The pinned assertion: tor's SocksPort accepts NO_AUTH (reply
// exactly 05 00). A future tor offering no acceptable method (05 FF) or a
// different version fails here — that is the digest-bump gate firing.
func (s *ulSocksSession) greetingNoAuth() error {
	if _, err := s.stdin.Write([]byte{ulVer5, 0x01, ulMethodNoAuth}); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}
	reply, err := s.readFull(2)
	if err != nil {
		return err
	}
	if reply[0] != ulVer5 {
		return fmt.Errorf("greeting reply version %d (want 5)", reply[0])
	}
	if reply[1] != ulMethodNoAuth {
		return fmt.Errorf("tor rejected NO_AUTH (method-selection reply 0x%02x) — "+
			"tor no longer accepts credential-less SOCKS5 under the rendered config", reply[1])
	}
	return nil
}

// greetingUserPass negotiates method 0x02 and completes the RFC 1929
// username/password subnegotiation. The username is the isolation
// credential (FR-002); tor does not verify it, so any non-empty pair works.
func (s *ulSocksSession) greetingUserPass(username string) error {
	if _, err := s.stdin.Write([]byte{ulVer5, 0x01, ulMethodUserPass}); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}
	reply, err := s.readFull(2)
	if err != nil {
		return err
	}
	if reply[0] != ulVer5 || reply[1] != ulMethodUserPass {
		return fmt.Errorf("tor did not select username/password method (reply 0x%02x 0x%02x)",
			reply[0], reply[1])
	}
	if len(username) == 0 || len(username) > 255 {
		return fmt.Errorf("username length %d outside RFC 1929 bounds", len(username))
	}
	req := append([]byte{0x01, byte(len(username))}, username...)
	req = append(req, 0x01, 'x') // PLEN=1, PASSWD="x" (unused by tor; RFC 1929 §2)
	if _, err := s.stdin.Write(req); err != nil {
		return fmt.Errorf("userpass write: %w", err)
	}
	authReply, err := s.readFull(2)
	if err != nil {
		return err
	}
	if authReply[0] != 0x01 || authReply[1] != 0x00 {
		return fmt.Errorf("username/password subnegotiation failed (reply 0x%02x 0x%02x)",
			authReply[0], authReply[1])
	}
	return nil
}

// connect sends the SOCKS5 CONNECT for host — the BARE hostname, no port:
// ATYP=domain DST.ADDR is the name alone and DST.PORT (appended below)
// carries the port separately. No local name resolution ever happens
// (FR-007/SOCKS5h). REP != 0 fails with the RFC 1928 §6 name so a digest
// bump that breaks egress names what changed. (Run 4's root cause lived
// here: the stream-status match target "onion:80" was passed whole, tor
// read a 59-char onion and rejected it as "malformed hostname" — named by
// the tor log tail this file now attaches to every deadline failure.)
func (s *ulSocksSession) connect(host string) error {
	if len(host) == 0 || len(host) > 255 {
		return fmt.Errorf("dest length %d outside ATYP=domain bounds", len(host))
	}
	req := append([]byte{ulVer5, ulCmdConnect, 0x00, ulAtypDomain, byte(len(host))}, host...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], ulOnionPort)
	req = append(req, portBytes[:]...)
	if _, err := s.stdin.Write(req); err != nil {
		return fmt.Errorf("connect request write: %w", err)
	}
	head, err := s.readFull(4)
	if err != nil {
		return err
	}
	if head[0] != ulVer5 {
		return fmt.Errorf("connect reply version %d (want 5)", head[0])
	}
	if head[1] != ulRepSucceeded {
		return fmt.Errorf("SOCKS5 CONNECT failed: %s (%d)", ulRepName(head[1]), head[1])
	}
	switch head[3] {
	case ulAtypIPv4:
		_, err = s.readFull(4 + 2)
	case ulAtypDomain:
		var ln []byte
		if ln, err = s.readFull(1); err == nil {
			_, err = s.readFull(int(ln[0]) + 2)
		}
	case ulAtypIPv6:
		_, err = s.readFull(16 + 2)
	default:
		return fmt.Errorf("connect reply ATYP %d unrecognized", head[3])
	}
	if err != nil {
		return err
	}
	return nil
}

// close ends the session: stdin close (nc reads EOF and exits), then a
// grace wait with kill backstop — the ControlPort.Close shape, minus QUIT
// (SOCKS has no goodbye; the TCP close IS the stream teardown).
func (s *ulSocksSession) close() error {
	if s == nil || s.cmd == nil {
		return nil
	}
	_ = s.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		return <-done
	}
}

// ulRepName names the RFC 1928 §6 reply codes used in error messages.
func ulRepName(rep byte) string {
	switch rep {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unassigned reply code"
	}
}

// ulStreamStatesTerminal are the stream-status states a lingering dead
// stream can carry; they never count toward the exactly-N match.
var ulStreamStatesTerminal = map[string]bool{
	"CLOSED": true, "FAILED": true, "DETACHED": true,
}

// ulStreamsAtTarget reads GETINFO stream-status through the T062 helper and
// returns the circuit IDs of the live streams whose target matches, with
// their states for logging. Reply lines are 4 fields per the control-spec
// (<StreamID> <Status> <CircID> <Target>); shorter lines are skipped rather
// than fatal because the exactly-N count assertion below — not this loop —
// is what guards the pin.
func ulStreamsAtTarget(conn *ControlPort, target string) (circIDs, states []string, err error) {
	lines, err := conn.Command("GETINFO stream-status")
	if err != nil {
		return nil, nil, fmt.Errorf("GETINFO stream-status: %w", err)
	}
	for _, ln := range lines {
		fields := strings.Fields(ln)
		if len(fields) < 4 || fields[3] != target || ulStreamStatesTerminal[fields[1]] {
			continue
		}
		circIDs = append(circIDs, fields[2])
		states = append(states, fields[1])
	}
	return circIDs, states, nil
}

// ulWaitStreams polls until exactly want live streams match target and
// returns their circuit IDs in stream-status order. It fails (rather than
// skips) at the deadline: a count that never lands is a pin failure or a
// harness bug, and both must be loud.
func ulWaitStreams(t *testing.T, conn *ControlPort, target string, want int, wait time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(wait)
	var circIDs, states []string
	for {
		var err error
		circIDs, states, err = ulStreamsAtTarget(conn, target)
		if err != nil {
			t.Fatalf("stream-status poll: %v", err)
		}
		if len(circIDs) == want {
			return circIDs
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected exactly %d live stream(s) to %s within %s; saw %d (%s)",
				want, target, wait, len(circIDs), truncate(strings.Join(states, ",")))
		}
		time.Sleep(ulPollEvery)
	}
}

// ulCircuitBuilt cross-checks the shared circuit exists in GETINFO
// circuit-status with status BUILT — tor's circuit-level surface must agree
// with its stream-level one (guards against misparsing stream-status and
// against the stream hanging off a circuit circuit-status no longer lists).
func ulCircuitBuilt(t *testing.T, conn *ControlPort, circID string) bool {
	t.Helper()
	lines, err := conn.Command("GETINFO circuit-status")
	if err != nil {
		t.Fatalf("GETINFO circuit-status: %v", err)
	}
	prefix := circID + " "
	for _, ln := range lines {
		if strings.HasPrefix(ln, prefix) && strings.Contains(ln, " BUILT ") {
			return true
		}
	}
	return false
}
