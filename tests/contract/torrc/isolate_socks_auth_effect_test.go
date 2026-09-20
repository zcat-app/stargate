//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// isolate_socks_auth_effect_test.go is the live-sidecar gate named by
// contracts/torrc.md §"isolate_socks_auth_effect_test.go" and spec.md
// §"User Story 2" acceptance scenario 1. live_sidecar_test.go (T032/T087)
// proved Tor LOADED IsolateSOCKSAuth (the GETCONF surface); this file proves
// the directive has its EFFECT: two SOCKS5 streams that differ ONLY in their
// username/password auth identity attach to DISTINCT circuits. A torrc whose
// flag Tor accepts-but-ignores passes every static and GETCONF gate and
// still silently merges first-party streams onto one circuit — the exact
// cross-origin correlation this feature exists to prevent (Principle III).
//
// The probe is deliberately sharpest-case: BOTH CONNECTs target the SAME
// destination (the spec-pinned reference onion) and differ only in UNAME —
// tor's default shares one circuit across streams regardless of
// destination, so circuit distinctness here isolates the auth identity as
// the only variable. This gates the US2 acceptance scenario 1 behavioral
// property on the real sidecar: distinct first-party identities MUST NOT
// merge onto one circuit (Principle III). Grounded caveat (mutation
// battery, 2026-09-07, recorded in the ticket §Notes): on the pinned tor
// 0.4.9, distinct auth identities isolate even with IsolateSOCKSAuth
// dropped from the config, so a dropped flag is caught by the STATIC gates
// (T029 byte-match, T030 invariants, T032 live GETCONF) — not by this
// behavioral test. What no other gate catches is the behavioral property
// itself: a tor upgrade that ever merges distinct-identity streams fails
// here, loudly, at the digest-bump PR's live run. The
// two-distinct-destinations variant through port 8881 is T059;
// same-origin intentional sharing (scenario 3) is T060; the 10-onion scale
// (scenario 2 / SC-002) is T061; the NO_AUTH no-username companion (streams
// share a default circuit by design) is T058a.
//
// Transport (FR-012): the native SOCKS Unix socket stays Tor-private; no
// host TCP dial exists. The SOCKS5 bytes are driven from Go through
// `docker compose exec -T tor nc -U /run/tor-fabric/private/tor-socks.sock`.
// Circuit state is read through T062's
// cookie-authenticated control-port helper (tests/contract/tor), never from
// tor log lines (torrc.md #8: Stargate does not consume Tor logs as data).
// UNAME values are opaque isolation keys (socks5-auth.md: the first-party
// domain, NOT a credential); the pair uses RFC 2606 .invalid names so the
// test asserts isolation behaviour, not any real party's routability.
//
// Wire shapes are CALIBRATED against the production tor image (external-
// control doctrine: the running sidecar is the positive control, not this
// file's own assumptions), observed 2026-09-07:
//
//	stream-status entry:   <StreamID> <STATE> <CircuitID> <host:port>
//	  (STATE ∈ {SENTCONNECT, SUCCEEDED, …} — the stream is attached to its
//	  circuit from SENTCONNECT onward; the reference onion's service closes
//	  the idle connection after ~30s, so the entry disappears while the
//	  SOCKS session is still open — polls must run close to each CONNECT).
//	circuit-status entry:  <CircuitID> BUILT … SOCKS_USERNAME="<UNAME>"
//	  SOCKS_PASSWORD="<PASSWD>" — tor tags each isolated circuit with the
//	  auth identity that built it, which is the identity→circuit
//	  correlation key here (stable for the circuit's lifetime).
//
// A future tor that changes either shape fails this test LOUDLY at its poll
// deadline with the raw reply attached — the digest-bump PR (Principle IV
// manual-promotion gate) is where that recalibration is meant to surface.
// One more observed quirk the parsers absorb: a single-entry GETINFO value
// arrives glue-attached to its keyword (`250-stream-status=<first entry>`,
// no data block), so `<keyword>=` prefixes are stripped before parsing
// (isoStripKeywordPrefix).
//
// stargate:cadence docker — brings up the tor service and needs the live
// Tor network for bootstrap + onion rendezvous, so it is build-tagged out
// of the hermetic PR gate and runs in the named Docker job
// (`STARGATE_TEST_TAGS=docker scripts/verify.sh`), or manually:
//
//	cd tests/contract && go test -tags docker ./torrc/ -run TestIsolateSOCKSAuthDistinctCircuits -v -timeout 20m
//
// Skip guards mirror T019b/T032/T062 (docker CLI absent / daemon
// unreachable).
package torrc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zcat-app/stargate/tests/contract/tor"
)

const (
	isoComposeProject = "stargate-t058-test"

	isoUpDeadline   = 5 * time.Minute  // compose build + start (T032/T062's ceiling)
	isoBootDeadline = 5 * time.Minute  // tor bootstrap on the live network
	isoPollEvery    = 2 * time.Second  // control-port poll cadence (T032's pace)
	isoDialDeadline = 2 * time.Minute  // per-CONNECT: circuit build + onion rendezvous slack (T033's per-attempt bound)
	isoStreamGrace  = 15 * time.Second // stream-status visibility window after CONNECT success (entry appears ≤2s after CONNECT; the reference onion closes idle conns ~30s in, so poll CLOSE to the event)

	isoOverallDeadline = 18 * time.Minute // whole-test ctx (test -timeout 20m is the outer bound)

	// isoTarget is the spec-pinned reference onion (spec.md §"User
	// Story 1" — DuckDuckGo's v3 onion, the stable publicly reachable
	// target). Both CONNECTs use it: the variable under test is the auth
	// identity, never the destination (see the file header).
	isoTarget = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443"

	// The two auth identities — opaque isolation keys simulating the
	// extension's UNAME = first-party domain (socks5-auth.md §"Username/
	// password sub-negotiation"). RFC 2606 .invalid: deliberately
	// non-routable names, not real parties.
	isoAuthA = "first-party-a.t058.invalid"
	isoAuthB = "first-party-b.t058.invalid"

	// Fixed PASSWD so UNAME is the only isolation differentiator. In
	// production the DP dials the sidecar with the inbound UNAME verbatim
	// and an EMPTY password (PLEN=0): the bearer token is validated at the
	// data plane and never re-sent upstream (FR-002/FR-006/FR-007;
	// forward/tor.go dialUpstream). Against tor directly this constant is
	// simply the second half of the SOCKS auth identity.
	isoPasswd = "stargate-t058"
)

// TestIsolateSOCKSAuthDistinctCircuits — see the file header for the
// property under test and the subtest map to the ticket acceptance.
//
// Subtests:
//   - SidecarBootstraps: cold image-baked torrc parses, control session
//     authenticates through the T062 helper (cookie from the invariant-#11
//     path), Tor reaches PROGRESS=100.
//   - FirstStreamAttaches: SOCKS5 userpass CONNECT (identity A) to the
//     reference onion succeeds; a stream for the target is visible in
//     stream-status (attached from SENTCONNECT onward) and its circuit
//     carries the identity A tag in circuit-status.
//   - SecondStreamDistinctUsernameAttaches: same target, identity B; the
//     NEW stream (streamID set-difference — both streams share one target
//     string, so the ID set is the correlation key) is recorded.
//   - CircuitsAreDistinct: the two circuit IDs differ AND both appear as
//     identity-tagged entries in GETINFO circuit-status — the literal
//     control-port query contracts/torrc.md names. A shared circuit fails
//     the test.
func TestIsolateSOCKSAuthDistinctCircuits(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), isoOverallDeadline)
	defer cancel()

	// Reuse the package-level findRepoRoot pinned by T029; the compose
	// file + env live under compose/ at that same root (T032/T062's shape).
	repoRoot := findRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}

	// Cleanup BEFORE any compose invocation (T019b/T032/T062 ordering
	// rationale: a partially-successful up must not orphan the project —
	// an orphaned tor sidecar keeps circuits alive, exposing the operator's
	// guards after the test "ended").
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer downCancel()
		if out, err := isoCompose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	upCtx, upCancel := context.WithTimeout(ctx, isoUpDeadline)
	defer upCancel()
	if out, err := isoCompose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up -d --build tor (cold volume, image-baked torrc): %v\n%s", err, out)
	}

	cfg := tor.ControlPortConfig{Project: isoComposeProject, ComposeFile: composeFile, EnvFile: envFile}

	var conn *tor.ControlPort
	t.Cleanup(func() {
		if conn != nil {
			_ = conn.Close()
		}
	})

	// (a) SidecarBootstraps — poll cookie read + Connect + AUTHENTICATE to
	// a deadline (tor writes the cookie and starts listening during
	// startup; T062's LiveAuthenticatesWithCookieFromVolume shape), then
	// poll the session to PROGRESS=100 (T062's LiveBootstrapPollViaSession
	// shape).
	t.Run("SidecarBootstraps", func(t *testing.T) {
		deadline := time.Now().Add(isoBootDeadline)
		var lastErr error
		for {
			if time.Now().After(deadline) {
				t.Fatalf("no authenticated control session within %s (cookie read + connect + AUTHENTICATE): %v",
					isoBootDeadline, lastErr)
			}
			cookie, err := tor.ReadCookie(ctx, cfg)
			if err == nil {
				var c *tor.ControlPort
				c, err = tor.Connect(ctx, cfg)
				if err == nil {
					if err = c.Authenticate(cookie); err == nil {
						conn = c
					} else {
						_ = c.Close()
					}
				} else {
					_ = c.Close()
				}
			}
			if conn != nil {
				break
			}
			lastErr = err
			time.Sleep(isoPollEvery)
		}

		bootDeadline := time.Now().Add(isoBootDeadline)
		var last string
		for {
			lines, err := conn.Command("GETINFO status/bootstrap-phase")
			if err != nil {
				t.Fatalf("GETINFO status/bootstrap-phase mid-poll: %v (last: %s)", err, last)
			}
			last = strings.Join(lines, " | ")
			if strings.Contains(last, "PROGRESS=100") {
				t.Logf("OK: Tor bootstrapped: %s", isoTruncate(last))
				break
			}
			if time.Now().After(bootDeadline) {
				t.Fatalf("tor did not reach PROGRESS=100 within %s; last phase: %s", isoBootDeadline, isoTruncate(last))
			}
			time.Sleep(isoPollEvery)
		}
	})

	authed := func(t *testing.T) {
		if conn == nil {
			t.Fatal("no authenticated control session — SidecarBootstraps failed")
		}
	}

	var (
		socksA, socksB    *isoSocksConn
		streamA, circuitA string
		streamB, circuitB string
		snapshotA         map[string]string
	)
	t.Cleanup(func() {
		for _, c := range []*isoSocksConn{socksA, socksB} {
			if err := c.Close(); err != nil {
				t.Logf("socks session close (best-effort cleanup): %v", err)
			}
		}
	})

	// (b) FirstStreamAttaches — identity A's CONNECT must succeed and the
	// resulting stream must be visible in stream-status (it exists from
	// SENTCONNECT onward; see the calibrated wire shapes in the header).
	// Poll CLOSE to the connect: the reference onion closes the idle
	// connection after ~30s and the entry disappears with it.
	t.Run("FirstStreamAttaches", func(t *testing.T) {
		authed(t)
		c, err := isoDialSocks(ctx, cfg, isoAuthA, isoPasswd, isoTarget)
		if err != nil {
			t.Fatalf("SOCKS5 CONNECT as %q to %s: %v", isoAuthA, isoTarget, err)
		}
		socksA = c

		deadline := time.Now().Add(isoStreamGrace)
		var raw []string
		for {
			lines, err := conn.Command("GETINFO stream-status")
			if err != nil {
				t.Fatalf("GETINFO stream-status: %v", err)
			}
			raw = lines
			snap := isoParseStreamsFor(lines, isoTarget)
			if len(snap) == 1 {
				for sid, cid := range snap {
					streamA, circuitA = sid, cid
				}
				snapshotA = snap
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected exactly 1 attached stream for %s within %s of CONNECT, saw %d; "+
					"stream-status raw reply:\n%s",
					isoTarget, isoStreamGrace, len(snap), strings.Join(raw, "\n"))
			}
			time.Sleep(isoPollEvery)
		}

		// Identity-tag cross-check, run close to the event while circuit A
		// certainly lives: its circuit-status entry must carry identity A.
		tagDeadline := time.Now().Add(isoStreamGrace)
		for {
			lines, err := conn.Command("GETINFO circuit-status")
			if err != nil {
				t.Fatalf("GETINFO circuit-status (identity check): %v", err)
			}
			if _, ok := isoCircuitStatusFor(lines, circuitA, isoAuthA); ok {
				break
			}
			if time.Now().After(tagDeadline) {
				t.Fatalf("circuit %s (stream %s) never carried SOCKS_USERNAME=%q in circuit-status within %s — "+
					"either the stream attached to a foreign circuit or tor stopped tagging circuits with their "+
					"auth identity (recalibrate the wire shape); raw reply:\n%s",
					circuitA, streamA, isoAuthA, isoStreamGrace, strings.Join(lines, "\n"))
			}
			time.Sleep(isoPollEvery)
		}
		t.Logf("OK: first stream attached: stream %s → circuit %s (tagged %q)", streamA, circuitA, isoAuthA)
	})

	// (c) SecondStreamDistinctUsernameAttaches — identity B, SAME target.
	// Both streams share one target string, so the new stream is the
	// streamID set-difference against the first snapshot (stream IDs are
	// unique within a tor run). Only the fresh entry is required: identity
	// A's stream may already have been closed by the onion (~30s idle
	// timeout) if this subtest's rendezvous is slow — its circuit is
	// already recorded and re-checked in CircuitsAreDistinct.
	t.Run("SecondStreamDistinctUsernameAttaches", func(t *testing.T) {
		authed(t)
		if streamA == "" {
			t.Fatal("first stream not recorded — FirstStreamAttaches failed")
		}
		c, err := isoDialSocks(ctx, cfg, isoAuthB, isoPasswd, isoTarget)
		if err != nil {
			t.Fatalf("SOCKS5 CONNECT as %q to %s: %v", isoAuthB, isoTarget, err)
		}
		socksB = c

		deadline := time.Now().Add(isoStreamGrace)
		var raw []string
		for {
			lines, err := conn.Command("GETINFO stream-status")
			if err != nil {
				t.Fatalf("GETINFO stream-status: %v", err)
			}
			raw = lines
			snap := isoParseStreamsFor(lines, isoTarget)
			var fresh []string
			for sid := range snap {
				if _, seen := snapshotA[sid]; !seen {
					fresh = append(fresh, sid)
				}
			}
			if len(fresh) == 1 {
				streamB, circuitB = fresh[0], snap[fresh[0]]
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected the identity-B stream for %s to appear within %s of the second CONNECT, "+
					"saw %d stream(s) (%d fresh, need exactly 1 fresh); stream-status raw reply:\n%s",
					isoTarget, isoStreamGrace, len(snap), len(fresh), strings.Join(raw, "\n"))
			}
			time.Sleep(isoPollEvery)
		}
		t.Logf("OK: second stream attached: stream %s → circuit %s", streamB, circuitB)
	})

	// (d) CircuitsAreDistinct — the load-bearing assertion. If both streams
	// landed on one circuit, IsolateSOCKSAuth is not in effect and the
	// privacy property US2 advertises does not hold (Principle III).
	// Cross-checked through the literal query the contract names, using
	// tor's per-circuit auth-identity tags: circuit A's entry must carry
	// SOCKS_USERNAME=<identity A>, circuit B's identity B.
	t.Run("CircuitsAreDistinct", func(t *testing.T) {
		authed(t)
		if circuitA == "" || circuitB == "" {
			t.Fatalf("streams not recorded — attach subtests failed (A: stream %s circuit %s; B: stream %s circuit %s)",
				streamA, circuitA, streamB, circuitB)
		}
		if circuitA == circuitB {
			t.Errorf("BOTH streams attached to circuit %s (streams %s and %s, distinct UNAMEs %q/%q, same target %s) — "+
				"IsolateSOCKSAuth had NO effect: torrc invariant #1 regression; per-first-party stream isolation "+
				"does not hold (Principle III). Check `docker compose -p %s logs tor` for a config-parse warning.",
				circuitA, streamA, streamB, isoAuthA, isoAuthB, isoTarget, isoComposeProject)
			return
		}
		lines, err := conn.Command("GETINFO circuit-status")
		if err != nil {
			t.Fatalf("GETINFO circuit-status: %v", err)
		}
		for _, tc := range []struct{ cid, uname string }{{circuitA, isoAuthA}, {circuitB, isoAuthB}} {
			_, ok := isoCircuitStatusFor(lines, tc.cid, tc.uname)
			if !ok {
				t.Errorf("circuit %s (stream identity %q) is not a tagged entry in GETINFO circuit-status "+
					"(%d reply lines) — the stream's circuit is missing or carries a foreign identity; raw reply:\n%s",
					tc.cid, tc.uname, len(lines), strings.Join(lines, "\n"))
			}
		}
		// Unconditional on arrival: the equal-circuit case early-returned
		// above, so reaching here means the circuits are distinct.
		t.Logf("OK: distinct circuits — stream %s (UNAME %q) → circuit %s; stream %s (UNAME %q) → circuit %s",
			streamA, isoAuthA, circuitA, streamB, isoAuthB, circuitB)
	})
}

// isoSocksConn is one SOCKS5 client session whose TCP socket terminates
// inside the tor container (FR-012 — no host-side dial exists). The Go side
// owns the protocol bytes; nc is a dumb pipe.
type isoSocksConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr *bytes.Buffer
	cancel context.CancelFunc
	closed bool
}

// isoDialSocks performs the full SOCKS5 handshake — method negotiation
// offering only RFC 1929 userpass (0x02; the isolation property under test
// is keyed on the auth identity — the NO_AUTH side is T058a's pin, not
// this test's), the userpass subnegotiation, then CONNECT (ATYP=0x03,
// SOCKS5h: the name is routed by tor, never resolved locally — FR-007 /
// Principle III) — and leaves the session open with the stream attached.
//
// The handshake is bounded by isoDialDeadline via a process-kill watchdog
// (exec pipes carry no read deadlines); on success the watchdog is stopped
// and the session lives until Close (or the parent context's expiry).
func isoDialSocks(parent context.Context, cfg tor.ControlPortConfig, uname, passwd, target string) (*isoSocksConn, error) {
	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, "docker",
		"compose", "-p", cfg.Project,
		"-f", cfg.ComposeFile,
		"--env-file", cfg.EnvFile,
		"exec", "-T", "tor", "nc", "-U", "/run/tor-fabric/private/tor-socks.sock")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("socks session stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("socks session stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("socks session start (docker compose exec tor nc -U private SOCKS): %w: %s",
			err, strings.TrimSpace(stderr.String()))
	}

	c := &isoSocksConn{cmd: cmd, stdin: stdin, stdout: stdout, stderr: &stderr, cancel: cancel}
	watch := time.AfterFunc(isoDialDeadline, func() {
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
	})
	err = c.handshake(uname, passwd, target)
	watch.Stop()
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// handshake speaks the SOCKS5 byte protocol over the exec pipes.
func (c *isoSocksConn) handshake(uname, passwd, target string) error {
	// (1) Method negotiation: VER=5, one method, USERNAME/PASSWORD (0x02).
	if err := c.writeAll([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	greeting := make([]byte, 2)
	if err := c.readFull(greeting, "method negotiation reply"); err != nil {
		return err
	}
	if greeting[0] != 0x05 {
		return fmt.Errorf("socks method reply: unexpected VER 0x%02x", greeting[0])
	}
	if greeting[1] != 0x02 {
		return fmt.Errorf("socks method reply: tor chose method 0x%02x, want 0x02 (username/password) — "+
			"the isolation property under test is keyed on the auth identity", greeting[1])
	}

	// (2) RFC 1929 subnegotiation: VER=1, ULEN UNAME, PLEN PASSWD.
	sub := make([]byte, 0, 3+len(uname)+len(passwd))
	sub = append(sub, 0x01, byte(len(uname)))
	sub = append(sub, uname...)
	sub = append(sub, byte(len(passwd)))
	sub = append(sub, passwd...)
	if err := c.writeAll(sub); err != nil {
		return err
	}
	auth := make([]byte, 2)
	if err := c.readFull(auth, "userpass subnegotiation reply"); err != nil {
		return err
	}
	if auth[0] != 0x01 || auth[1] != 0x00 {
		return fmt.Errorf("socks userpass subnegotiation rejected (VER 0x%02x STATUS 0x%02x)", auth[0], auth[1])
	}

	// (3) CONNECT with ATYP=0x03 (domain).
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 0xffff {
		return fmt.Errorf("target %q: port %q is not a 16-bit port", target, portStr)
	}
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	req = append(req, portBytes[:]...)
	if err := c.writeAll(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if err := c.readFull(head, "CONNECT reply header"); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("socks CONNECT reply: unexpected VER 0x%02x", head[0])
	}
	if rep := head[1]; rep != 0x00 {
		return fmt.Errorf("socks CONNECT rep=%d (%s) for target %s", rep, isoRepName(rep), target)
	}
	// Drain the bound address + port so the reply is fully consumed before
	// the session is declared established (a partial read here would leave
	// reply bytes to be misread as data later).
	var bound []byte
	switch atyp := head[3]; atyp {
	case 0x01:
		bound = make([]byte, 4)
	case 0x04:
		bound = make([]byte, 16)
	case 0x03:
		l := make([]byte, 1)
		if err := c.readFull(l, "CONNECT reply domain length"); err != nil {
			return err
		}
		bound = make([]byte, int(l[0]))
	default:
		return fmt.Errorf("socks CONNECT reply: unexpected ATYP 0x%02x", atyp)
	}
	if err := c.readFull(bound, "CONNECT reply bound address"); err != nil {
		return err
	}
	trailer := make([]byte, 2)
	if err := c.readFull(trailer, "CONNECT reply bound port"); err != nil {
		return err
	}
	return nil
}

// writeAll sends one full protocol message. Errors carry the transport
// diagnostics (nc/docker stderr), never protocol traffic.
func (c *isoSocksConn) writeAll(b []byte) error {
	if _, err := c.stdin.Write(b); err != nil {
		return fmt.Errorf("socks write: %w: %s", err, strings.TrimSpace(c.stderr.String()))
	}
	return nil
}

// readFull reads exactly len(b) bytes, attaching transport diagnostics on
// EOF (a dead nc/container presents as EOF, same as the control-port
// helper's readLine).
func (c *isoSocksConn) readFull(b []byte, what string) error {
	if _, err := io.ReadFull(c.stdout, b); err != nil {
		return fmt.Errorf("socks read (%s): %w: %s", what, err, strings.TrimSpace(c.stderr.String()))
	}
	return nil
}

// Close tears the session down. Observed behavior (calibration runs,
// 2026-09-07): openbsd nc does NOT exit when its stdin hits EOF — it stays
// in receive mode until the remote side closes, and tor holds the SOCKS
// connection open. The kill grace is therefore the EXPECTED close path,
// not an error path: stdin EOF (best-effort half-close), a 5s wait for an
// nc that will not come, then Kill. The wait error (always "signal:
// killed" on success) is returned so a genuinely broken transport still
// surfaces at the caller; cleanup callers log it best-effort. Safe to call
// twice (the handshake failure path closes first).
func (c *isoSocksConn) Close() error {
	if c == nil || c.closed {
		return nil
	}
	c.closed = true
	_ = c.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- c.cmd.Wait() }()
	select {
	case err := <-done:
		c.cancel()
		return err
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
		err := <-done
		c.cancel()
		return err
	}
}

// isoStripKeywordPrefix removes the keyword glue tor puts on single-value
// reply lines: when a GETINFO value has no embedded newline tor sends it as
// `250-<keyword>=<value>` — the T062 helper surfaces that payload as
// `<keyword>=<value>`, glue included — while multi-entry values arrive as
// dot-stuffed data blocks whose lines are bare. Stream/circuit entries
// begin with a decimal ID, which never collides with the keyword.
func isoStripKeywordPrefix(ln string) string {
	for _, kw := range []string{"stream-status=", "circuit-status="} {
		if strings.HasPrefix(ln, kw) {
			return strings.TrimPrefix(ln, kw)
		}
	}
	return ln
}

// isoParseStreamsFor extracts streamID → circuitID for every ATTACHED
// stream whose target equals the given address, from a GETINFO
// stream-status reply. Calibrated against the production image (header):
// each entry is `<StreamID> <STATE> <CircuitID> <host:port>` — the stream
// is attached to its circuit from SENTCONNECT onward, and both SENTCONNECT
// and SUCCEEDED prove attachment, so both are accepted. Lines that are not
// stream entries (the reply's framing lines the T062 helper surfaces as
// payloads) are skipped by the digit guards; an unrecognised shape yields
// an empty map and the caller's deadline failure prints the raw reply.
func isoParseStreamsFor(lines []string, target string) map[string]string {
	out := make(map[string]string)
	for _, ln := range lines {
		f := strings.Fields(isoStripKeywordPrefix(strings.TrimSpace(ln)))
		if len(f) < 4 || !isoDigits(f[0]) || !isoDigits(f[2]) {
			continue
		}
		if f[1] != "SENTCONNECT" && f[1] != "SUCCEEDED" {
			continue
		}
		if f[3] != target {
			continue
		}
		out[f[0]] = f[2]
	}
	return out
}

// isoCircuitStatusFor returns the GETINFO circuit-status entry whose leading
// circuit ID matches circuitID and which carries the given auth identity's
// SOCKS_USERNAME tag (calibrated shape: `<CircuitID> BUILT …
// SOCKS_USERNAME="<UNAME>" SOCKS_PASSWORD="…"` — tor tags every isolated
// circuit with the identity that built it). ok=false means the circuit is
// absent or carries a foreign identity; callers print the raw reply.
func isoCircuitStatusFor(lines []string, circuitID, uname string) (string, bool) {
	prefix := circuitID + " "
	tag := `SOCKS_USERNAME="` + uname + `"`
	for _, ln := range lines {
		ln = isoStripKeywordPrefix(strings.TrimSpace(ln))
		if strings.HasPrefix(ln, prefix) && strings.Contains(ln, tag) {
			return ln, true
		}
	}
	return "", false
}

// isoCompose runs `docker compose -p <isoComposeProject> …` — same shape as
// the sibling suites' runners, which each bake their own project const in
// (T019b/T032/T062 precedent); not importable across packages.
func isoCompose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{
		"compose", "-p", isoComposeProject,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	return exec.CommandContext(ctx, "docker", full...).CombinedOutput()
}

// isoDigits reports whether s is a non-empty decimal digit string (tor
// stream/circuit IDs).
func isoDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// isoRepName names a SOCKS5 CONNECT reply code (RFC 1928 §6) so a failed
// rendezvous surfaces with a meaningful message instead of a bare number.
func isoRepName(rep byte) string {
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

// isoTruncate bounds a diagnostic line (hygiene: failures stay readable,
// never dump unbounded protocol output).
func isoTruncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
