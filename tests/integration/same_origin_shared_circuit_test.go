//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// same_origin_shared_circuit_test.go is T060: the integration test pinning
// US2 acceptance scenario 3 — two CONNECTs to the SAME first-party `.onion`
// attach to the SAME circuit ID. This is the design, not a leak: the
// extension sets the SOCKS5 username to the request's first-party domain
// (FR-002), the data plane forwards that UNAME verbatim upstream (FR-007,
// pinned hermetically by T047's TestForwardPassesUNAMEVerbatimAsUpstream-
// Username), and tor's IsolateSOCKSAuth consolidates streams presenting the
// SAME credential onto one circuit. If a future tor release isolates
// same-identity streams, this test fails in the digest-bump PR's live run
// (Principle IV) and the consolidation half of FR-002's isolation semantics
// is renegotiated with a SECURITY-DECISIONS.md entry — the same consumption
// path as T058/T058a.
//
// Transport grounding (T060 §Analysis): the ticket, unlike T059, names no
// "through port 8881" leg. The through-8881 composition is covered by
// composition — T047's hermetic UNAME pin (data-plane half) + this test's
// live tor-side pin (sidecar half) + T033's release-cadence full-vertical
// load. Exercising the DP live here would require a host→9050 path, which
// FR-012 forbids publishing and no suite may fabricate; the harness's only
// sanctioned channel into the compose-internal sidecar is the exec/nc
// transport T032/T058a/T062 established. The sessions below therefore ride
// `docker compose exec -T tor nc -U /run/tor-fabric/private/tor-socks.sock` with the Go side owning
// the RFC 1928/1929 wire bytes — the T058a machinery, aimed at the
// same-credential case. The control side (cookie auth, circuit reads) is
// the landed T062 helper, consumed unmodified.
//
// Destination: the spec-pinned reference onion (T033's t033Onion —
// tests/integration/onion_load_test.go, same module, constant duplicated
// there; provenance in that header). CONNECT carries only host:port, so
// "different resources on the same origin" is modelled as two independent
// concurrent CONNECT sessions to the same origin — the isolation key
// (username) is resource-invariant by design, and no HTTP payload exchange
// belongs to this pin (T033's surface).
//
// Subtest 2 is the external-calibration control (doctrine 780aaae): the
// SAME stream-reading machinery must observe DISTINCT circuits under
// DISTINCT usernames (T058's effect). Without it, subtest 1's "shared"
// verdict is indistinguishable from "cannot detect isolation".
//
// Deadline model: identical to T058a's — fine-grained deadlines bound the
// polls; the suite-wide context bounds everything else; a hung rendezvous
// kills nc via CommandContext and surfaces as a short read.
//
// stargate:cadence docker — this suite BRINGS UP the tor service and needs
// the live Tor network for bootstrap, so it is build-tagged out of the
// hermetic PR gate and runs in the named Docker job
// (`STARGATE_TEST_TAGS=docker scripts/verify.sh`), or manually:
//
//	cd tests/integration && go test -tags docker -run TestSameOriginSharedCircuit -v -timeout 25m
//
// Skip guards mirror T058a (docker CLI absent / daemon unreachable).
package integration

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	tor "github.com/zcat-app/stargate/tests/contract/tor"
)

// soComposeProject namespaces every compose invocation this suite issues so
// it never collides with operator-authored state or sibling suites running
// in parallel (stargate-t033-test, stargate-t058a-test, T058's project, …).
// Each suite bakes its own project const into its own runner (the
// T032/T062/T058a re-implementation precedent; T121 owns the future hoist).
const soComposeProject = "stargate-t060-test"

// soOnion is the reference onion this suite CONNECTs to, and — as the
// SOCKS5 USERNAME — the first-party domain value the extension sends and
// the DP forwards verbatim in production (FR-002). Same spec-pinned
// address as T033's t033Onion; port 80 is its documented HTTP port. Port
// 443 is deliberately NOT used: the pin is about circuit attachment, not
// TLS (T058a's rationale).
const (
	soOnion     = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	soOnionPort = 80
)

const (
	soUpDeadline   = 5 * time.Minute  // compose build + start (mirrors T058a/T062)
	soBootDeadline = 5 * time.Minute  // tor bootstrap on the live network (T032's deadline)
	soPollEvery    = 2 * time.Second  // control-port poll cadence (T062's pace)
	soConnectWait  = 3 * time.Minute  // first-working-CONNECT window (T058a's cold-boot insurance)
	soStreamWait   = 90 * time.Second // stream-attach wait (the 90 s T033's retry window had before T208)
	soDrainWait    = 30 * time.Second // wait for the prior subtest's streams to detach
	soDownDeadline = 90 * time.Second // compose down cleanup
	soExecDead     = 15 * time.Second // compose logs deadline (forensics only)
	soOverallDead  = 18 * time.Minute // whole-suite ctx (test -timeout 25m is the outer bound;
	// worst-case arithmetic: up 5m + control-session 5m + boot 5m + boot 5m +
	// connect 3m + stream 1.5m + drain 0.5m + connect 1.5m + stream 1.5m ≈
	// 23.5m — TWO sequential soBootDeadline windows precede the subtests
	// (soBootstrapControl's control-session acquisition, then
	// soWaitBootstrapped's PROGRESS=100 wait each get a fresh 5m), so
	// soOverallDead=18m intentionally fires first in the stacked worst: a
	// hung environment surfaces as a loud ctx/transport failure (nc killed
	// via CommandContext) rather than a per-phase deadline message, and
	// never a hang. Deadline model inherited from T058a, with this
	// double-window correction to its arithmetic)
)

// SOCKS5 wire constants (RFC 1928/1929) — the subset T060 needs.
const (
	soVer5           = 0x05
	soMethodUserPass = 0x02
	soCmdConnect     = 0x01
	soAtypIPv4       = 0x01
	soAtypDomain     = 0x03
	soAtypIPv6       = 0x04
	soRepSucceeded   = 0x00
)

func TestSameOriginSharedCircuit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), soOverallDead)
	defer cancel()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := tor.CommandOutput(ctx, exec.CommandContext(ctx, "docker", "info")); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}

	repoRoot := t033FindRepoRoot(t) // same package, untagged (onion_load_test.go)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}
	cfg := tor.ControlPortConfig{Project: soComposeProject, ComposeFile: composeFile, EnvFile: envFile}

	// Cleanup BEFORE up (T019b's ordering rationale: a partially-successful
	// up must not orphan the project when the test aborts).
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), soDownDeadline)
		defer downCancel()
		if out, err := soCompose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// Signal-safe teardown (T033's redteam finding): t.Cleanup fires on
	// t.Fatalf but not on SIGINT/SIGTERM, and a detached compose project
	// keeps the Tor sidecar's circuits — and the operator's IP at the
	// entry guards — alive after the test is believed over.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		dCtx, dCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dCancel()
		if out, err := soCompose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "signal %v: compose down (best-effort): %v\n%s", sig, err, out)
		}
		os.Exit(1)
	}()

	upCtx, upCancel := context.WithTimeout(ctx, soUpDeadline)
	defer upCancel()
	if out, err := soCompose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up -d --build tor: %v\n%s", err, out)
	}

	// Authenticated control session, polled through the startup window
	// (T062's live bootstrap shape), then held until PROGRESS=100: SOCKS
	// CONNECT before full bootstrap fails with a circuit error that would
	// masquerade as the behaviour pin failing.
	conn := soBootstrapControl(t, ctx, cfg)
	t.Cleanup(func() { _ = conn.Close() })
	soWaitBootstrapped(t, conn)

	// Subtests are sequential (no t.Parallel): the calibration subtest
	// needs the share subtest's streams drained first, and each subtest
	// owns its sessions outright (T058a's subtest hygiene).
	target := fmt.Sprintf("%s:%d", soOnion, soOnionPort)

	// Subtest 1 — the ticket assertion: two same-username (same first-party
	// origin) streams attach to the SAME circuit.
	t.Run("SameOriginStreamsShareCircuit", func(t *testing.T) {
		s1, s2 := soPairConnect(t, ctx, cfg, target,
			func(s *soSocksSession, _ int) error { return s.greetingUserPass(soOnion) }, soConnectWait)
		circIDs := soWaitStreams(t, conn, target, 2, soStreamWait)
		shared := circIDs[0]
		if shared == "0" {
			t.Fatalf("same-origin streams reported unattached (CircID 0): %v", circIDs)
		}
		if circIDs[1] != shared {
			t.Errorf("SAME-username streams attached to DIFFERENT circuits (%s vs %s) — "+
				"tor no longer consolidates same-credential streams under IsolateSOCKSAuth; "+
				"FR-002's same-origin circuit sharing (US2 scenario 3) is broken at the source",
				shared, circIDs[1])
		}
		if !soCircuitBuilt(t, conn, shared) {
			t.Errorf("shared circuit %s not found BUILT in GETINFO circuit-status — "+
				"stream-status and circuit-status disagree (reading bug or tor surface change)", shared)
		}
		t.Logf("OK: both same-origin streams share circuit %s (also BUILT in circuit-status)", shared)
		// Close before the calibration subtest so its exactly-two count sees
		// only its own streams.
		_ = s1.close()
		_ = s2.close()
	})

	// Subtest 2 — positive control (external-calibration doctrine, 780aaae):
	// the same reading machinery must DETECT isolation — two distinct
	// usernames land on distinct circuits (T058's effect, re-observed here
	// so this suite's share verdict is calibrated in its own run). If this
	// control fails, the environment cannot distinguish shared from
	// isolated, and the share assertion above is unproven rather than green.
	t.Run("CalibrationDistinctUsernamesDiverge", func(t *testing.T) {
		// Drain: the previous subtest's streams must be gone before we
		// count exactly two again (tor may linger a closed stream briefly).
		soWaitStreams(t, conn, target, 0, soDrainWait)

		s3, s4 := soPairConnect(t, ctx, cfg, target,
			func(s *soSocksSession, i int) error {
				if i == 0 {
					return s.greetingUserPass("t060-alpha")
				}
				return s.greetingUserPass("t060-beta")
			}, soStreamWait)
		circIDs := soWaitStreams(t, conn, target, 2, soStreamWait)
		if circIDs[0] == "0" || circIDs[1] == "0" {
			t.Fatalf("calibration streams unattached (CircID 0): %v", circIDs)
		}
		if circIDs[0] == circIDs[1] {
			t.Errorf("DISTINCT usernames shared circuit %s — tor no longer isolates "+
				"credential-bearing streams; the T058 isolation contract and FR-002's "+
				"per-first-party isolation are broken at the source, and this suite's "+
				"share assertion above is uncalibrated", circIDs[0])
		}
		t.Logf("OK: distinct usernames on distinct circuits (%s vs %s) — detection machinery calibrated",
			circIDs[0], circIDs[1])
		_ = s3.close()
		_ = s4.close()
	})
}

// soCompose runs `docker compose -p <soComposeProject> …`. The project const
// is baked into THIS suite's runner — reusing a sibling's runner would point
// this suite's up/down at the SIBLING's project while its exec transports
// use ours (found live by T058a's first run; T121 owns the future hoist).
func soCompose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{
		"compose", "-p", soComposeProject,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	return tor.CommandOutput(ctx, exec.CommandContext(ctx, "docker", full...))
}

// soPairConnect dials and greets two fresh SOCKS sessions, CONNECTs both to
// target, and returns the live sessions. Each attempt is a full fresh
// dial+greet+connect pair; on any per-attempt failure both sessions are
// closed and the attempt is retried until the wait deadline, because an
// onion CONNECT right after PROGRESS=100 fails transiently while tor
// fetches descriptors and warms its circuit builder (T033's retry-window
// precedent; T058a observed it live as REP=1 within seconds of bootstrap).
// greet selects the credential per connection (index 0/1) — that is the
// whole variable under test: identical for the share subtest, distinct for
// the calibration. Both sessions stay open from the first CONNECT onward,
// so the two streams coexist on the sidecar — the observable meaning of
// scenario 3's "in parallel". A genuine pin regression fails every attempt
// identically and the deadline Fatal carries the last error verbatim.
func soPairConnect(t *testing.T, ctx context.Context, cfg tor.ControlPortConfig, target string,
	greet func(s *soSocksSession, idx int) error, wait time.Duration) (s1, s2 *soSocksSession) {
	t.Helper()
	opCtx, opCancel := context.WithTimeout(ctx, wait)
	defer opCancel()
	var lastErr error
	for {
		if opCtx.Err() != nil {
			t.Fatalf("no working SOCKS5 connection pair to %s within %s: %v (tor notice log tail: %s)",
				target, wait, lastErr, soTorLogTail(t, ctx, cfg))
		}
		lastErr = nil
		s1, s2 = soDialSocks(t, ctx, cfg), soDialSocks(t, ctx, cfg)
		for idx, s := range []*soSocksSession{s1, s2} {
			if err := s.operation(opCtx, func() error { return greet(s, idx) }); err != nil && lastErr == nil {
				lastErr = fmt.Errorf("greeting (connection %d): %w", idx+1, err)
			}
		}
		if lastErr == nil {
			for idx, s := range []*soSocksSession{s1, s2} {
				if err := s.operation(opCtx, func() error { return s.connect(soOnion) }); err != nil && lastErr == nil {
					lastErr = fmt.Errorf("CONNECT (connection %d): %w", idx+1, err)
				}
			}
		}
		if lastErr == nil {
			return s1, s2
		}
		_ = s1.close()
		_ = s2.close()
		tor.Pause(opCtx, soPollEvery)
	}
}

// soTorLogTail returns the last 15 notice lines from the tor container for
// failure forensics. Safe to print: the torrc bakes `Log notice stdout` +
// `SafeLogging 1` (torrc contract invariants #8–#9 — the same channel the
// healthcheck and operators read), so addresses are scrubbed at the source.
func soTorLogTail(t *testing.T, ctx context.Context, cfg tor.ControlPortConfig) string {
	t.Helper()
	logCtx, logCancel := context.WithTimeout(ctx, soExecDead)
	defer logCancel()
	out, err := soCompose(logCtx, cfg.ComposeFile, cfg.EnvFile, "logs", "--tail", "15", "tor")
	if err != nil {
		return fmt.Sprintf("(logs unavailable: %v)", err)
	}
	return "\n" + string(out)
}

// soBootstrapControl polls ReadCookie + Connect + Authenticate until tor is
// accepting control sessions (T062's live bootstrap shape).
func soBootstrapControl(t *testing.T, ctx context.Context, cfg tor.ControlPortConfig) *tor.ControlPort {
	t.Helper()
	opCtx, opCancel := context.WithTimeout(ctx, soBootDeadline)
	defer opCancel()
	var lastErr error
	for {
		if opCtx.Err() != nil {
			t.Fatalf("no authenticated control session within %s: %v", soBootDeadline, lastErr)
		}
		var err error
		var c *tor.ControlPort
		cookie, cookieErr := tor.ReadCookie(opCtx, cfg)
		if cookieErr == nil {
			c, err = tor.Connect(ctx, cfg)
			if err == nil {
				err = c.AuthenticateContext(opCtx, cookie)
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
		tor.Pause(opCtx, soPollEvery)
	}
}

// soWaitBootstrapped polls GETINFO status/bootstrap-phase until PROGRESS=100
// (the T062 shape; the SOCKS service is only useful after full bootstrap).
func soWaitBootstrapped(t *testing.T, conn *tor.ControlPort) {
	t.Helper()
	opCtx, opCancel := context.WithTimeout(conn.Context(), soBootDeadline)
	defer opCancel()
	var last string
	for {
		lines, err := conn.CommandContext(opCtx, "GETINFO status/bootstrap-phase")
		if err != nil {
			t.Fatalf("GETINFO status/bootstrap-phase mid-poll: %v (last: %s)", err, last)
		}
		last = strings.Join(lines, " | ")
		if strings.Contains(last, "PROGRESS=100") {
			t.Logf("OK: tor bootstrapped: %s", soTruncate(last))
			return
		}
		if opCtx.Err() != nil {
			t.Fatalf("tor did not reach PROGRESS=100 within %s; last phase: %s", soBootDeadline, soTruncate(last))
		}
		tor.Pause(opCtx, soPollEvery)
	}
}

// soSocksSession is one SOCKS5 connection to the tor SocksPort over the
// in-container exec/nc transport — the T062 ControlPort pattern aimed at
// the private Unix socket with the Go side owning the RFC 1928/1929 wire bytes (T058a's
// session shape). Sequential, single-goroutine: each step writes then reads
// its bounded reply.
type soSocksSession struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	r       *bufio.Reader
	stderr  *tor.DiagnosticBuffer
	session *tor.ProcessSession
}

// soDialSocks opens the exec/nc session to the Tor-private Unix socket inside the tor
// container. Failures name the transport; the SOCKS dialogue itself starts
// only after Start succeeds. The session lives until close or until ctx is
// cancelled (CommandContext backstop).
func soDialSocks(t *testing.T, ctx context.Context, cfg tor.ControlPortConfig) *soSocksSession {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-p", soComposeProject,
		"-f", cfg.ComposeFile, "--env-file", cfg.EnvFile,
		"exec", "-T", "tor", "nc", "-U", tor.SocksSocketPath)
	session, err := tor.StartProcess(ctx, cmd)
	if err != nil {
		t.Fatalf("socks session start (private SOCKS): %v", err)
	}
	s := &soSocksSession{cmd: cmd, stdin: session.Stdin, r: bufio.NewReader(session.Stdout), stderr: session.Diagnostics, session: session}
	t.Cleanup(func() { _ = s.close() })
	return s
}

// readFull reads exactly n bytes with the transport diagnostics attached on
// short read (a dead nc presents as EOF here). Every n is a small fixed or
// length-capped size, so no runaway-read surface exists.
func (s *soSocksSession) readFull(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, fmt.Errorf("socks reply short read (want %d bytes): %w: %s",
			n, err, strings.TrimSpace(s.stderr.String()))
	}
	return buf, nil
}

// greetingUserPass negotiates method 0x02 and completes the RFC 1929
// username/password subnegotiation. The username is the isolation
// credential (FR-002) — in production the DP forwards it verbatim from the
// extension; tor does not verify it, so any non-empty pair works. The
// password is the T058a dummy (`01 'x'`, RFC 1929 §2 shape — the extra
// 0x01 byte that once shipped here desynced the stream, T058a §Notes #5).
func (s *soSocksSession) greetingUserPass(username string) error {
	if _, err := s.stdin.Write([]byte{soVer5, 0x01, soMethodUserPass}); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}
	reply, err := s.readFull(2)
	if err != nil {
		return err
	}
	if reply[0] != soVer5 || reply[1] != soMethodUserPass {
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
// carries the port separately (T058a §Notes #4 — passing "onion:80" whole
// once read a 59-char onion and died as "malformed hostname" on every
// attempt). No local name resolution ever happens (FR-007/SOCKS5h).
// REP != 0 fails with the RFC 1928 §6 name so a digest bump that breaks
// egress names what changed.
func (s *soSocksSession) connect(host string) error {
	if len(host) == 0 || len(host) > 255 {
		return fmt.Errorf("dest length %d outside ATYP=domain bounds", len(host))
	}
	req := append([]byte{soVer5, soCmdConnect, 0x00, soAtypDomain, byte(len(host))}, host...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], soOnionPort)
	req = append(req, portBytes[:]...)
	if _, err := s.stdin.Write(req); err != nil {
		return fmt.Errorf("connect request write: %w", err)
	}
	head, err := s.readFull(4)
	if err != nil {
		return err
	}
	if head[0] != soVer5 {
		return fmt.Errorf("connect reply version %d (want 5)", head[0])
	}
	if head[1] != soRepSucceeded {
		return fmt.Errorf("SOCKS5 CONNECT failed: %s (%d)", soRepName(head[1]), head[1])
	}
	switch head[3] {
	case soAtypIPv4:
		_, err = s.readFull(4 + 2)
	case soAtypDomain:
		var ln []byte
		if ln, err = s.readFull(1); err == nil {
			_, err = s.readFull(int(ln[0]) + 2)
		}
	case soAtypIPv6:
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
func (s *soSocksSession) operation(ctx context.Context, fn func() error) error {
	return s.session.Operation(ctx, fn)
}

func (s *soSocksSession) close() error {
	if s == nil {
		return nil
	}
	return s.session.Close(nil)
}

// soRepName names the RFC 1928 §6 reply codes used in error messages.
func soRepName(rep byte) string {
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

// soStreamStatesTerminal are the stream-status states a lingering dead
// stream can carry; they never count toward the exactly-N match.
var soStreamStatesTerminal = map[string]bool{
	"CLOSED": true, "FAILED": true, "DETACHED": true,
}

// soStreamsAtTarget reads GETINFO stream-status through the T062 helper and
// returns the circuit IDs of the live streams whose target matches, with
// their states for logging. Reply lines are 4 fields per the control-spec
// (<StreamID> <Status> <CircID> <Target>); shorter lines are skipped rather
// than fatal because the exactly-N count assertion below — not this loop —
// is what guards the pin (T058a's parsing rule).
func soStreamsAtTarget(ctx context.Context, conn *tor.ControlPort, target string) (circIDs, states []string, err error) {
	lines, err := conn.CommandContext(ctx, "GETINFO stream-status")
	if err != nil {
		return nil, nil, fmt.Errorf("GETINFO stream-status: %w", err)
	}
	for _, ln := range lines {
		fields := strings.Fields(ln)
		if len(fields) < 4 || fields[3] != target || soStreamStatesTerminal[fields[1]] {
			continue
		}
		circIDs = append(circIDs, fields[2])
		states = append(states, fields[1])
	}
	return circIDs, states, nil
}

// soWaitStreams polls until exactly want live streams match target and
// returns their circuit IDs in stream-status order. It fails (rather than
// skips) at the deadline: a count that never lands is a pin failure or a
// harness bug, and both must be loud.
func soWaitStreams(t *testing.T, conn *tor.ControlPort, target string, want int, wait time.Duration) []string {
	t.Helper()
	opCtx, opCancel := context.WithTimeout(conn.Context(), wait)
	defer opCancel()
	var circIDs, states []string
	for {
		var err error
		circIDs, states, err = soStreamsAtTarget(opCtx, conn, target)
		if err != nil {
			t.Fatalf("stream-status poll: %v", err)
		}
		if len(circIDs) == want {
			return circIDs
		}
		if opCtx.Err() != nil {
			t.Fatalf("expected exactly %d live stream(s) to %s within %s; saw %d (%s)",
				want, target, wait, len(circIDs), soTruncate(strings.Join(states, ",")))
		}
		tor.Pause(opCtx, soPollEvery)
	}
}

// soCircuitBuilt cross-checks the shared circuit exists in GETINFO
// circuit-status with status BUILT — tor's circuit-level surface must agree
// with its stream-level one (guards against misparsing stream-status and
// against the stream hanging off a circuit circuit-status no longer lists).
func soCircuitBuilt(t *testing.T, conn *tor.ControlPort, circID string) bool {
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

// soTruncate bounds a diagnostic line inside error messages (T062's M4/M5
// hygiene: diagnostics are bounded).
func soTruncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// T210 uses the actual subprocess helper with successful dialogue before EOF.
const t210soTransport = `#!/usr/bin/python3 -B
import os,sys,time,threading
mode=os.environ.get("T210_SOCKS_MODE","dialogue")
def read(n):
 b=b""
 while len(b)<n:
  chunk=os.read(0,n-len(b))
  if not chunk: sys.exit(0)
  b+=chunk
 return b
def eof():
 def diag():
  end=time.monotonic()+1
  while time.monotonic()<end: os.write(2,b"synthetic SOCKS transport diagnostic\n"*128)
 thread=threading.Thread(target=diag);thread.start();os.close(1);thread.join()
if os.environ.get("T210_REQUIRE_UNIX")=="1" and "nc -U /run/tor-fabric/private/tor-socks.sock" not in " ".join(sys.argv[1:]):
 os.write(2,b"wrong SOCKS transport argv\n");sys.exit(64)
if mode=="blocked-write":time.sleep(30);sys.exit(0)
greeting=read(3)
if mode=="blocked-read":time.sleep(30);sys.exit(0)
os.write(1,bytes([5,greeting[2]]))
if greeting[2]==2:
 head=read(2);read(head[1]);plen=read(1);read(plen[0]);os.write(1,b"\x01\x00")
if os.environ.get("T210_CONNECT")=="1":
 head=read(5);read(head[4]+2);os.write(1,b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
if mode=="dialogue":eof()
else:
 while os.read(0,4096):pass
`

func TestT210SODiagnostics(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "docker"), []byte(t210soTransport), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("T210_SOCKS_MODE", "dialogue")
	t.Setenv("T210_CONNECT", "0")
	cfg := tor.ControlPortConfig{Project: "t210-fixture", ComposeFile: "/fixture/compose.yml", EnvFile: "/fixture/local.env"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := soDialSocks(t, ctx, cfg)
	if err := s.greetingUserPass("synthetic-user"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		if _, err := s.readFull(2); err == nil {
			t.Fatal("EOF transport returned success")
		}
	}
}

func TestT210SOOperationBounds(t *testing.T) {
	for _, mode := range []string{"blocked-read", "blocked-write"} {
		t.Run(mode, func(t *testing.T) {
			tmp := t.TempDir()
			if err := os.WriteFile(filepath.Join(tmp, "docker"), []byte(t210soTransport), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("T210_SOCKS_MODE", mode)
			t.Setenv("T210_CONNECT", "0")
			cfg := tor.ControlPortConfig{Project: "t210-fixture", ComposeFile: "/fixture/compose.yml", EnvFile: "/fixture/local.env"}
			lifetime, cancelLifetime := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelLifetime()
			s := soDialSocks(t, lifetime, cfg)
			defer s.close()
			if mode == "blocked-write" {
				fd := int(s.stdin.(*os.File).Fd())
				if err := syscall.SetNonblock(fd, true); err != nil {
					t.Fatal(err)
				}
				for {
					_, err := syscall.Write(fd, make([]byte, 4096))
					if err == syscall.EAGAIN {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := syscall.SetNonblock(fd, false); err != nil {
					t.Fatal(err)
				}
			}
			op, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				fn := func() error { return s.greetingUserPass("synthetic-user") }
				if bounded, ok := any(s).(interface {
					operation(context.Context, func() error) error
				}); ok {
					done <- bounded.operation(op, fn)
				} else {
					done <- fn()
				}
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stalled operation returned success")
				}
			case <-time.After(700 * time.Millisecond):
				cancelLifetime()
				_ = s.cmd.Process.Kill()
				_ = s.stdin.Close()
				<-done
				t.Error("helper ignored its operation context at real pipe I/O")
			}
		})
	}
}

func TestT210SOUnixTransport(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "docker"), []byte(t210soTransport), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("T210_SOCKS_MODE", "dialogue")
	t.Setenv("T210_REQUIRE_UNIX", "1")
	t.Setenv("T210_CONNECT", "0")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s := soDialSocks(t, ctx, tor.ControlPortConfig{Project: "t210", ComposeFile: "/fixture/compose.yml", EnvFile: "/fixture/local.env"})
	if err := s.greetingUserPass("synthetic-user"); err != nil {
		t.Fatalf("private Unix SOCKS negotiation: %v", err)
	}
}
