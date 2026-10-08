//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// T061 — SC-002 measurement (specs/001-tor-route/spec.md §SC-002, as
// amended 2026-09-07): 100 sequential CONNECTs, each labeled with one of
// the 100 distinct first-party `.onion` strings from the committed
// synthetic corpus (tests/integration/synthetic_onion_corpus.txt, T063),
// assert the Tor sidecar reports ≥95 distinct identity-tagged circuit IDs.
// This statistic does not establish completed destination CONNECTs or
// browser/data-plane coverage. The corpus string is the SOCKS5 username — the isolation key
// the extension sends in production (FR-007; tor never parses it as an
// address, so the corpus's Ed25519-invalid keys are harmless here). Each
// CONNECT targets the spec-pinned reachable reference onion, because the
// sidecar builds no circuit toward an unpublished address (amendment
// evidence: this ticket's §Notes; SECURITY-DECISIONS.md 2026-09-07).
//
// Circuit attribution is T058's correlation key: `IsolateSOCKSAuth` tags
// each isolated circuit with `SOCKS_USERNAME="<UNAME>"` in `GETINFO
// circuit-status` for the circuit's lifetime, so the per-CONNECT poll is
// a direct substring match and the circuit ID is the entry's first field.
//
// stargate:cadence docker — brings up the tor service and needs the live
// Tor network for bootstrap + the reference onion's reachability, so it
// is build-tagged out of the hermetic PR gate (compile-checked via
// `go vet -tags`) and runs in the named Docker job
// (`STARGATE_TEST_TAGS=docker scripts/verify.sh`), or manually:
//
//	cd tests/integration && go test -tags docker -run TestCircuitIsolationCorpus -v -timeout 45m
//
// Skip guards mirror T033/T058/T062 (docker CLI absent / daemon
// unreachable).
package integration

import (
	"bytes"
	"context"
	"encoding/base32"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	tor "github.com/zcat-app/stargate/tests/contract/tor"
)

const (
	t061Project = "stargate-t061-test"

	// The spec-pinned reachable reference target (spec.md §Assumptions —
	// reference-target bullet). Every corpus-labeled CONNECT dials THIS
	// address; the variable under test is the isolation identity, never
	// the destination (T058's design, scaled to the corpus).
	t061Target = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443"

	// Fixed PASSWD: the upstream identity the data plane sends is
	// (UNAME, empty password) — forward/tor.go dials with User only —
	// but a non-empty constant keeps the SOCKS5 userpass shape identical
	// to T058's (isoPasswd) while UNAME stays the only varying axis.
	// Fixed, non-secret harness constant, kept T058-shaped: the
	// pre-commit gitleaks gate flags higher-entropy strings.
	t061Passwd = "stargate-t061"

	t061UpDeadline      = 5 * time.Minute  // compose build + start (T032/T062 ceiling)
	t061BootDeadline    = 5 * time.Minute  // tor bootstrap on the live network
	t061PollEvery       = 2 * time.Second  // control-port poll cadence (T032's pace)
	t061CaptureDeadline = 30 * time.Second // per-CONNECT tagged-circuit window (~5 s observed in probes)
	t061OverallDeadline = 40 * time.Minute // whole-test ctx (test -timeout 45m is the outer bound)
	t061DistinctMin     = 95               // amended SC-002: ≥95 of 100
	t061CorpusLines     = 100
	t061ReferenceTarget = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion" // A4: must be absent from the corpus
)

// t061SocksSession is one CONNECT left open inside the tor container
// until its tagged circuit has been captured.
type t061SocksSession struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	session *tor.ProcessSession
}

// TestCircuitIsolationCorpus — the amended SC-002 measurement. See the
// file header for the property and the mechanism; subtests:
//
//   - CorpusIsValid: load-time validation of the committed corpus per
//     T063 §Acceptance A5, FAILing with the offending line number before
//     any CONNECT is issued (no verify.sh gate inspects a .txt file, so
//     a post-hoc hand edit must not surface as a confusing
//     circuit-isolation failure).
//   - SidecarBootstraps: cold image-baked torrc parses; control session
//     authenticates through the T062 helper; tor reaches PROGRESS=100.
//   - CorpusIdentitiesGetDistinctCircuits: 100 sequential corpus-labeled
//     CONNECT attempts are measured by ≥95 distinct tagged circuit IDs —
//     the SC-002 assertion. Identities that produced no tagged circuit
//     within the window are named in the output.
func TestCircuitIsolationCorpus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), t061OverallDeadline)
	defer cancel()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := tor.CommandOutput(ctx, exec.CommandContext(ctx, "docker", "info")); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}

	repoRoot := t033FindRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}

	// Cleanup BEFORE any compose invocation (T019b/T032/T058 ordering
	// rationale: a partially-successful up must not orphan the project —
	// an orphaned tor sidecar keeps circuits alive, exposing the
	// operator's guards after the test "ended").
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer downCancel()
		if out, err := t061Compose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// Signal-safe teardown (T033): t.Cleanup does not run on SIGINT/SIGTERM
	// during the long run; an orphaned sidecar must not outlive the test.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		dCtx, dCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dCancel()
		if out, err := t061Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "signal %v: compose down (best-effort): %v\n%s", sig, err, out)
		}
		os.Exit(1)
	}()

	// (1) CorpusIsValid — before anything else.
	var corpus []string
	t.Run("CorpusIsValid", func(t *testing.T) {
		corpus = t061ValidateCorpus(t)
	})

	// (2) SidecarBootstraps — bring up + authenticate.
	upCtx, upCancel := context.WithTimeout(ctx, t061UpDeadline)
	defer upCancel()
	if out, err := t061Compose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up -d --build tor (cold volume, image-baked torrc): %v\n%s", err, out)
	}

	cfg := tor.ControlPortConfig{Project: t061Project, ComposeFile: composeFile, EnvFile: envFile}

	var conn *tor.ControlPort
	t.Cleanup(func() {
		if conn != nil {
			_ = conn.Close()
		}
	})

	t.Run("SidecarBootstraps", func(t *testing.T) {
		opCtx, opCancel := context.WithTimeout(ctx, t061BootDeadline)
		defer opCancel()
		var lastErr error
		for {
			if opCtx.Err() != nil {
				t.Fatalf("no authenticated control session within %s (cookie read + connect + AUTHENTICATE): %v",
					t061BootDeadline, lastErr)
			}
			cookie, err := tor.ReadCookie(opCtx, cfg)
			if err == nil {
				var c *tor.ControlPort
				if c, err = tor.Connect(ctx, cfg); err == nil {
					if err = c.AuthenticateContext(opCtx, cookie); err == nil {
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
			tor.Pause(opCtx, t061PollEvery)
		}

		bootCtx, bootCancel := context.WithTimeout(ctx, t061BootDeadline)
		defer bootCancel()
		var last string
		for {
			lines, err := conn.CommandContext(bootCtx, "GETINFO status/bootstrap-phase")
			if err != nil {
				t.Fatalf("GETINFO status/bootstrap-phase mid-poll: %v (last: %s)", err, last)
			}
			last = strings.Join(lines, " | ")
			if strings.Contains(last, "PROGRESS=100") {
				t.Logf("OK: Tor bootstrapped: %s", t061Truncate(last))
				break
			}
			if bootCtx.Err() != nil {
				t.Fatalf("tor did not reach PROGRESS=100 within %s; last phase: %s", t061BootDeadline, t061Truncate(last))
			}
			tor.Pause(bootCtx, t061PollEvery)
		}
	})

	// (3) CorpusIdentitiesGetDistinctCircuits — the SC-002 measurement.
	t.Run("CorpusIdentitiesGetDistinctCircuits", func(t *testing.T) {
		if conn == nil {
			t.Fatal("no authenticated control session — SidecarBootstraps failed")
		}
		if len(corpus) != t061CorpusLines {
			t.Fatalf("corpus invalid (%d lines) — refusing to measure", len(corpus))
		}

		distinct := make(map[string]bool, t061CorpusLines)
		var misses, negotiationFailures []string
		issued := 0
		for i, uname := range corpus {
			captureCtx, captureCancel := context.WithTimeout(ctx, t061CaptureDeadline)
			sess, err := t061DialSocksContext(ctx, captureCtx, cfg, uname, t061Target)
			if err != nil {
				captureCancel()
				negotiationFailures = append(negotiationFailures, fmt.Sprintf("line %d (%s): negotiation: %v", i+1, uname, err))
				continue
			}
			issued++
			circID := func() string {
				defer captureCancel()
				return t061CaptureSessionCircuit(t, captureCtx, conn, uname, sess)
			}()
			if circID == "" {
				misses = append(misses, fmt.Sprintf("line %d (%s): no SOCKS_USERNAME-tagged circuit within %s",
					i+1, uname, t061CaptureDeadline))
				continue
			}
			distinct[circID] = true
			if (i+1)%20 == 0 {
				t.Logf("progress: %d/%d CONNECTs issued, %d distinct circuits so far", issued, len(corpus), len(distinct))
			}
		}

		t.Logf("SC-002: %d distinct identity-tagged circuit IDs across %d corpus identities (%d CONNECTs issued, %d negotiation failures, %d tagged-circuit misses): %s; %s", len(distinct), len(corpus), issued, len(negotiationFailures), len(misses), strings.Join(negotiationFailures, "; "), strings.Join(misses, "; "))
		if len(distinct) < t061DistinctMin {
			t.Fatalf("stream isolation measurement FAILED: %d distinct identity-tagged circuit IDs across %d corpus identities, need ≥%d (%d negotiation failures, %d tagged-circuit misses)", len(distinct), len(corpus), t061DistinctMin, len(negotiationFailures), len(misses))
		}
	})
}

// t061ValidateCorpus loads tests/integration/synthetic_onion_corpus.txt and
// asserts every property of T063 §Acceptance A5, failing with the offending
// 1-based line number. Runs before any CONNECT (see the subtest doc).
func t061ValidateCorpus(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(t033FindRepoRoot(t), "tests", "integration", "synthetic_onion_corpus.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	fail := func(lineNo int, format string, args ...any) []string {
		if lineNo > 0 {
			t.Fatalf("corpus invalid at line %d: %s", lineNo, fmt.Sprintf(format, args...))
		}
		t.Fatalf("corpus invalid: %s", fmt.Sprintf(format, args...))
		return nil
	}
	if bytes.IndexByte(raw, '\r') >= 0 {
		return fail(0, "CR byte found — LF-only required")
	}
	if !bytes.HasSuffix(raw, []byte("\n")) || bytes.HasSuffix(raw, []byte("\n\n")) {
		return fail(0, "file must end with exactly one trailing newline")
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != t061CorpusLines {
		return fail(0, "expected %d lines, got %d", t061CorpusLines, len(lines))
	}
	seen := make(map[string]bool, len(lines))
	shape := regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)
	for i, ln := range lines {
		lineNo := i + 1
		if !shape.MatchString(ln) {
			return fail(lineNo, "does not match ^[a-z2-7]{56}\\.onion$")
		}
		if seen[ln] {
			return fail(lineNo, "duplicate address")
		}
		seen[ln] = true
		if ln == t061ReferenceTarget {
			return fail(lineNo, "reference target must not appear in the corpus (A4)")
		}
		blob, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(ln[:56]))
		if err != nil || len(blob) != 35 {
			return fail(lineNo, "base32 decode failed: %v", err)
		}
		key, chk, version := blob[:32], blob[32:34], blob[34]
		if version != 0x03 {
			return fail(lineNo, "version byte is %#x, want 0x03", version)
		}
		h := sha3.New256()
		h.Write([]byte(".onion checksum"))
		h.Write(key)
		h.Write([]byte{version})
		if want := h.Sum(nil)[:2]; string(chk) != string(want) {
			return fail(lineNo, "checksum mismatch (computed %x, stored %x)", want, chk)
		}
	}
	t.Logf("OK: corpus valid — %d distinct, checksum-valid v3 strings", len(lines))
	return lines
}

// t061DialSocks opens one SOCKS5 session INSIDE the tor container
// (compose exec — FR-012: no host publication is manufactured), negotiates
// username/password auth with UNAME=<uname> (the isolation key) and
// PASSWD=<t061Passwd>, and writes the CONNECT for <target>. It deliberately
// does NOT read the BND reply: the session must stay open so the isolated
// circuit it triggered persists for the capture poll; the caller closes the
// session via close() once the circuit is recorded.
func t061DialSocks(parent context.Context, cfg tor.ControlPortConfig, uname, target string) (*t061SocksSession, error) {
	opCtx, cancel := context.WithTimeout(parent, t061CaptureDeadline)
	defer cancel()
	return t061DialSocksContext(parent, opCtx, cfg, uname, target)
}

func t061DialSocksContext(parent, opCtx context.Context, cfg tor.ControlPortConfig, uname, target string) (*t061SocksSession, error) {
	cmd := exec.CommandContext(parent, "docker", "compose",
		"-p", cfg.Project,
		"-f", cfg.ComposeFile,
		"--env-file", cfg.EnvFile,
		"exec", "-T", "tor", "nc", "-U", tor.SocksSocketPath)
	session, err := tor.StartProcess(parent, cmd)
	if err != nil {
		return nil, fmt.Errorf("socks session start (private SOCKS): %w", err)
	}
	stdin, stdout := session.Stdin, session.Stdout
	s := &t061SocksSession{cmd: cmd, stdin: stdin, session: session}

	err = session.Operation(opCtx, func() error {
		// (1) Method negotiation: VER=5, one method, USERNAME/PASSWORD (0x02).
		if _, err := stdin.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			_ = s.close()
			return fmt.Errorf("method negotiation write: %w", err)
		}
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(stdout, hdr); err != nil {
			_ = s.close()
			return fmt.Errorf("method negotiation reply: %w", err)
		}
		if hdr[1] != 0x02 {
			_ = s.close()
			return fmt.Errorf("sidecar chose method %#x, want 0x02 (username/password)", hdr[1])
		}

		// (2) Username/password sub-negotiation (RFC 1929): UNAME is the
		// first-party isolation key, PASSWD the fixed non-secret constant.
		if _, err := stdin.Write([]byte{0x01, byte(len(uname))}); err != nil {
			_ = s.close()
			return fmt.Errorf("auth write: %w", err)
		}
		if _, err := stdin.Write([]byte(uname)); err != nil {
			_ = s.close()
			return fmt.Errorf("auth write: %w", err)
		}
		if _, err := stdin.Write([]byte{byte(len(t061Passwd))}); err != nil {
			_ = s.close()
			return fmt.Errorf("auth write: %w", err)
		}
		if _, err := stdin.Write([]byte(t061Passwd)); err != nil {
			_ = s.close()
			return fmt.Errorf("auth write: %w", err)
		}
		apr := make([]byte, 2)
		if _, err := io.ReadFull(stdout, apr); err != nil {
			_ = s.close()
			return fmt.Errorf("auth reply: %w", err)
		}
		if apr[1] != 0x00 {
			_ = s.close()
			return fmt.Errorf("auth rejected (status %#x)", apr[1])
		}

		// (3) CONNECT request, ATYP=0x03 (domain — SOCKS5h: the name is routed
		// by tor, never resolved locally; FR-007 / Principle III).
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			_ = s.close()
			return fmt.Errorf("target %q: %w", target, err)
		}
		port, err := net.LookupPort("tcp", portStr)
		if err != nil {
			_ = s.close()
			return fmt.Errorf("target port %q: %w", portStr, err)
		}
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, host...)
		req = append(req, byte(port>>8), byte(port))
		if _, err := stdin.Write(req); err != nil {
			_ = s.close()
			return fmt.Errorf("connect write: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return s, nil
}

// close tears the session down: process kill + stdin close (the exec pipes
// carry no protocol goodbye), reaped before returning.
func (s *t061SocksSession) close() error {
	if s == nil {
		return nil
	}
	return s.session.Close(nil)
}

// t061CaptureSessionCircuit owns the negotiated session during circuit capture.
func t061CaptureSessionCircuit(t *testing.T, ctx context.Context, conn *tor.ControlPort, uname string, sess *t061SocksSession) string {
	// Fatalf runs Go defers: reap this negotiated child before the parent
	// lifetime ends, including a failed GETINFO (T210 AC4).
	defer sess.close()
	return t061CaptureCircuit(t, ctx, conn, uname)
}

// t061CaptureCircuit polls GETINFO circuit-status until an entry carries
// the identity tag SOCKS_USERNAME="<uname>" (T058's correlation key) and
// returns its circuit ID (the entry's first field). Empty string = no
// tagged circuit within the deadline — recorded as a miss by the caller,
// never fatal: an identity that produced no circuit is exactly the
// measurement signal SC-002's threshold absorbs.
func t061CaptureCircuit(t *testing.T, ctx context.Context, conn *tor.ControlPort, uname string) string {
	t.Helper()
	tag := `SOCKS_USERNAME="` + uname + `"`
	opCtx, opCancel := context.WithTimeout(ctx, t061CaptureDeadline)
	defer opCancel()
	for {
		if opCtx.Err() != nil {
			return ""
		}
		lines, err := conn.CommandContext(opCtx, "GETINFO circuit-status")
		if err != nil {
			t.Fatalf("GETINFO circuit-status while capturing %s: %v", uname, err)
		}
		for _, ln := range lines {
			if strings.Contains(ln, tag) {
				fields := strings.Fields(ln)
				if len(fields) == 0 {
					t.Fatalf("malformed circuit-status entry: %q", t061Truncate(ln))
				}
				return fields[0]
			}
		}
		if opCtx.Err() != nil {
			return ""
		}
		tor.Pause(opCtx, t061PollEvery)
	}
}

// t061Compose runs `docker compose -p <t061Project> …` (T032/T058's shape;
// own project namespace so parallel suites never collide).
func t061Compose(ctx context.Context, composeFile, envFile string, args ...string) (string, error) {
	full := append([]string{
		"compose", "-p", t061Project,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	out, err := tor.CommandOutput(ctx, exec.CommandContext(ctx, "docker", full...))
	return string(out), err
}

func t061Truncate(s string) string {
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

func TestT210CorpusUnixTransport(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "docker"), []byte(t210soTransport), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("T210_SOCKS_MODE", "keep")
	t.Setenv("T210_REQUIRE_UNIX", "1")
	t.Setenv("T210_CONNECT", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := t061DialSocks(ctx, tor.ControlPortConfig{Project: "t210", ComposeFile: "/fixture/compose.yml", EnvFile: "/fixture/local.env"}, "synthetic-user", "synthetic.invalid:80")
	if err != nil {
		t.Fatalf("private Unix SOCKS negotiation: %v", err)
	}
	defer s.close()
}

// Fatalf terminates only the nested test goroutine. A subprocess lets the outer
// regression expect that failure while checking ownership before cancellation.
func TestT210CorpusCaptureFailure(t *testing.T) {
	if os.Getenv("T210_CORPUS_FAILURE_CHILD") == "1" {
		tmp := t.TempDir()
		fixture := `#!/usr/bin/python3 -B
import os,sys
if sys.argv[-1].endswith("tor-socks.sock"):
 def read(n):
  b=b""
  while len(b)<n:
   c=os.read(0,n-len(b))
   if not c:sys.exit(0)
   b+=c
  return b
 read(3);os.write(1,b"\x05\x02")
 h=read(2);read(h[1]);n=read(1);read(n[0]);os.write(1,b"\x01\x00")
 h=read(5);read(h[4]+2)
 while os.read(0,4096):pass
else:
 for line in sys.stdin.buffer:
  if line.startswith(b"QUIT"):sys.exit(0)
  os.write(1,b"551 forced GETINFO failure\r\n")
`
		if err := os.WriteFile(filepath.Join(tmp, "docker"), []byte(fixture), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
		lifetime, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg := tor.ControlPortConfig{Project: "t210", ComposeFile: "/fixture/compose.yml", EnvFile: "/fixture/local.env"}
		sess, err := t061DialSocks(lifetime, cfg, "synthetic-user", "synthetic.invalid:80")
		if err != nil {
			t.Fatal(err)
		}
		defer sess.close() // Own RED cleanup, after the assertion under test.
		conn, err := tor.Connect(lifetime, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if t.Run("forced-capture-failure", func(t *testing.T) {
			t061CaptureSessionCircuit(t, lifetime, conn, "synthetic-user", sess)
		}) {
			t.Fatal("forced GETINFO failure was accepted")
		}
		if lifetime.Err() != nil {
			t.Fatal("parent lifetime cancelled before ownership check")
		}
		if sess.cmd.ProcessState == nil {
			t.Fatal("SOCKS child was not waited for after capture Fatalf")
		}
		if err := syscall.Kill(-sess.cmd.Process.Pid, 0); err != syscall.ESRCH {
			t.Fatalf("owned SOCKS process group survived capture failure: %v", err)
		}
		t.Log("SOCKS child reaped before parent cancellation")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestT210CorpusCaptureFailure$", "-test.v")
	cmd.Env = append(os.Environ(), "T210_CORPUS_FAILURE_CHILD=1")
	out, err := tor.CommandOutput(ctx, cmd)
	if err == nil || !bytes.Contains(out, []byte("forced GETINFO failure")) || !bytes.Contains(out, []byte("SOCKS child reaped before parent cancellation")) {
		t.Fatalf("expected capture Fatalf with reaped SOCKS child before lifetime cancellation: %v\n%s", err, out)
	}
}
