//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// T061 — SC-002 measurement (specs/001-tor-route/spec.md §SC-002, as
// amended 2026-09-07): 100 sequential CONNECTs, each labeled with one of
// the 100 distinct first-party `.onion` strings from the committed
// synthetic corpus (tests/integration/synthetic_onion_corpus.txt, T063),
// assert the Tor sidecar reports ≥95 distinct circuit IDs across the 100
// streams. The corpus string is the SOCKS5 username — the isolation key
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
	cmd   *exec.Cmd
	stdin io.WriteCloser
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
//     CONNECTs each produce a tagged circuit; ≥95 distinct circuit IDs —
//     the SC-002 assertion. Identities that produced no tagged circuit
//     within the window are named in the output.
func TestCircuitIsolationCorpus(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), t061OverallDeadline)
	defer cancel()

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
		deadline := time.Now().Add(t061BootDeadline)
		var lastErr error
		for {
			if time.Now().After(deadline) {
				t.Fatalf("no authenticated control session within %s (cookie read + connect + AUTHENTICATE): %v",
					t061BootDeadline, lastErr)
			}
			cookie, err := tor.ReadCookie(ctx, cfg)
			if err == nil {
				var c *tor.ControlPort
				if c, err = tor.Connect(ctx, cfg); err == nil {
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
			time.Sleep(t061PollEvery)
		}

		bootDeadline := time.Now().Add(t061BootDeadline)
		var last string
		for {
			lines, err := conn.Command("GETINFO status/bootstrap-phase")
			if err != nil {
				t.Fatalf("GETINFO status/bootstrap-phase mid-poll: %v (last: %s)", err, last)
			}
			last = strings.Join(lines, " | ")
			if strings.Contains(last, "PROGRESS=100") {
				t.Logf("OK: Tor bootstrapped: %s", t061Truncate(last))
				break
			}
			if time.Now().After(bootDeadline) {
				t.Fatalf("tor did not reach PROGRESS=100 within %s; last phase: %s", t061BootDeadline, t061Truncate(last))
			}
			time.Sleep(t061PollEvery)
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
		var misses []string
		for i, uname := range corpus {
			sess, err := t061DialSocks(ctx, cfg, uname, t061Target)
			if err != nil {
				misses = append(misses, fmt.Sprintf("line %d (%s): dial: %v", i+1, uname, err))
				continue
			}
			circID := t061CaptureCircuit(t, conn, uname)
			_ = sess.close()
			if circID == "" {
				misses = append(misses, fmt.Sprintf("line %d (%s): no SOCKS_USERNAME-tagged circuit within %s",
					i+1, uname, t061CaptureDeadline))
				continue
			}
			distinct[circID] = true
			if (i+1)%20 == 0 {
				t.Logf("progress: %d/%d CONNECTs issued, %d distinct circuits so far", i+1, len(corpus), len(distinct))
			}
		}

		t.Logf("SC-002: %d distinct circuit IDs across %d corpus-labeled CONNECTs (%d identities produced none): %s",
			len(distinct), len(corpus), len(misses), strings.Join(misses, "; "))
		if len(distinct) < t061DistinctMin {
			t.Fatalf("stream isolation measurement FAILED: %d distinct circuit IDs across %d CONNECTs, need ≥%d — the sidecar shared circuits across distinct first-party identities",
				len(distinct), len(corpus), t061DistinctMin)
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
	cmd := exec.CommandContext(parent, "docker", "compose",
		"-p", cfg.Project,
		"-f", cfg.ComposeFile,
		"--env-file", cfg.EnvFile,
		"exec", "-T", "tor", "nc", "127.0.0.1", "9050")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("socks session stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("socks session stdout pipe: %w", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("socks session start (docker compose exec tor nc 127.0.0.1 9050): %w: %s",
			err, strings.TrimSpace(stderr.String()))
	}
	s := &t061SocksSession{cmd: cmd, stdin: stdin}

	// (1) Method negotiation: VER=5, one method, USERNAME/PASSWORD (0x02).
	if _, err := stdin.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("method negotiation write: %w", err)
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(stdout, hdr); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("method negotiation reply: %w", err)
	}
	if hdr[1] != 0x02 {
		_ = s.close()
		return nil, fmt.Errorf("sidecar chose method %#x, want 0x02 (username/password)", hdr[1])
	}

	// (2) Username/password sub-negotiation (RFC 1929): UNAME is the
	// first-party isolation key, PASSWD the fixed non-secret constant.
	if _, err := stdin.Write([]byte{0x01, byte(len(uname))}); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("auth write: %w", err)
	}
	if _, err := stdin.Write([]byte(uname)); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("auth write: %w", err)
	}
	if _, err := stdin.Write([]byte{byte(len(t061Passwd))}); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("auth write: %w", err)
	}
	if _, err := stdin.Write([]byte(t061Passwd)); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("auth write: %w", err)
	}
	apr := make([]byte, 2)
	if _, err := io.ReadFull(stdout, apr); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("auth reply: %w", err)
	}
	if apr[1] != 0x00 {
		_ = s.close()
		return nil, fmt.Errorf("auth rejected (status %#x)", apr[1])
	}

	// (3) CONNECT request, ATYP=0x03 (domain — SOCKS5h: the name is routed
	// by tor, never resolved locally; FR-007 / Principle III).
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		_ = s.close()
		return nil, fmt.Errorf("target %q: %w", target, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		_ = s.close()
		return nil, fmt.Errorf("target port %q: %w", portStr, err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := stdin.Write(req); err != nil {
		_ = s.close()
		return nil, fmt.Errorf("connect write: %w", err)
	}
	return s, nil
}

// close tears the session down: process kill + stdin close (the exec pipes
// carry no protocol goodbye), reaped in the background.
func (s *t061SocksSession) close() error {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		go func() { _ = s.cmd.Wait() }()
	}
	if s.stdin != nil {
		return s.stdin.Close()
	}
	return nil
}

// t061CaptureCircuit polls GETINFO circuit-status until an entry carries
// the identity tag SOCKS_USERNAME="<uname>" (T058's correlation key) and
// returns its circuit ID (the entry's first field). Empty string = no
// tagged circuit within the deadline — recorded as a miss by the caller,
// never fatal: an identity that produced no circuit is exactly the
// measurement signal SC-002's threshold absorbs.
func t061CaptureCircuit(t *testing.T, conn *tor.ControlPort, uname string) string {
	t.Helper()
	tag := `SOCKS_USERNAME="` + uname + `"`
	deadline := time.Now().Add(t061CaptureDeadline)
	for {
		lines, err := conn.Command("GETINFO circuit-status")
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
		if !time.Now().Before(deadline) {
			return ""
		}
		time.Sleep(t061PollEvery)
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
	out, err := exec.CommandContext(ctx, "docker", full...).CombinedOutput()
	return string(out), err
}

func t061Truncate(s string) string {
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}
