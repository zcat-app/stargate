// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package tor

// Hermetic tests for the control-port client (control_port.go) — no build
// tag, no docker: these run in the PR gate under scripts/verify.sh. The
// parser and the error/secret discipline are the riskiest logic in the
// helper (T062 §Analysis M4/M5): every US2 circuit-isolation assertion
// reads `circuit-status` through it, so a parse regression must fail HERE,
// at PR cadence, not wait for the docker-cadence live self-test.
//
// The live transport (exec → nc → AUTHENTICATE against real tor) is gated
// by control_port_live_test.go (`//go:build docker`).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newTestConn wires a ControlPort to in-memory pipes: commands written to
// w are recorded in sent, replies are read from replies. This drives the
// REAL Command/readReply path (framing, parsing, bounds) without docker.
func newTestConn(replies string) (*ControlPort, *bytes.Buffer) {
	sent := &bytes.Buffer{}
	p := &ControlPort{
		w: bufio.NewWriter(sent),
		r: bufio.NewReader(strings.NewReader(replies)),
	}
	return p, sent
}

type postFlushCommander interface {
	CommandContextAfterFlush(context.Context, string, func(time.Time) error) ([]string, error)
}

func TestControlPortPostFlushHook(t *testing.T) {
	p, sent := newTestConn("250 OK\r\n")
	readProbe := &controlReadProbe{reader: strings.NewReader("250 OK\r\n")}
	p.r = bufio.NewReader(readProbe)
	commander, ok := any(p).(postFlushCommander)
	if !ok {
		t.Fatal("ControlPort does not implement CommandContextAfterFlush")
	}
	t.Run("AfterFlushBeforeReplyExactlyOnce", func(t *testing.T) {
		calls := 0
		lines, err := commander.CommandContextAfterFlush(context.Background(), "GETINFO version", func(at time.Time) error {
			calls++
			if at.IsZero() {
				t.Error("post-flush hook received zero timestamp")
			}
			if got := sent.String(); got != "GETINFO version\r\n" {
				t.Errorf("post-flush hook saw wire bytes %q", got)
			}
			if readProbe.started {
				t.Error("reply reading started before the post-flush hook")
			}
			return nil
		})
		if err != nil || strings.Join(lines, "\x00") != "OK" {
			t.Fatalf("CommandContextAfterFlush = %q, %v; want [OK], nil", lines, err)
		}
		if calls != 1 {
			t.Fatalf("post-flush hook called %d times, want exactly once", calls)
		}
		if !readProbe.started {
			t.Fatal("reply reading did not start after the post-flush hook")
		}
	})
	t.Run("FlushFailureDoesNotCallHook", func(t *testing.T) {
		p := &ControlPort{w: bufio.NewWriter(controlFailWriter{}), r: bufio.NewReader(strings.NewReader("250 OK\r\n"))}
		calls := 0
		_, err := commanderFor(t, p).CommandContextAfterFlush(context.Background(), "GETINFO version", func(time.Time) error {
			calls++
			return nil
		})
		if err == nil || calls != 0 {
			t.Fatalf("failed flush returned %v and invoked hook %d times; want error, zero calls", err, calls)
		}
	})
	t.Run("WriteStringFailureDoesNotCallHook", func(t *testing.T) {
		p := &ControlPort{w: bufio.NewWriter(controlFailWriter{}), r: bufio.NewReader(strings.NewReader("250 OK\r\n"))}
		if _, err := p.w.WriteString("seed"); err != nil {
			t.Fatalf("buffer synthetic payload: %v", err)
		}
		if err := p.w.Flush(); err == nil { // latch the writer error so the next WriteString itself fails
			t.Fatal("synthetic preflush unexpectedly succeeded")
		}
		calls := 0
		_, err := commanderFor(t, p).CommandContextAfterFlush(context.Background(), "GETINFO version", func(time.Time) error {
			calls++
			return nil
		})
		if err == nil || calls != 0 {
			t.Fatalf("failed WriteString returned %v and invoked hook %d times; want error, zero calls", err, calls)
		}
	})
	t.Run("PreCanceledContextDoesNotCallHook", func(t *testing.T) {
		p, sent := newTestConn("250 OK\r\n")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		_, err := commanderFor(t, p).CommandContextAfterFlush(ctx, "GETINFO version", func(time.Time) error {
			calls++
			return nil
		})
		if !errors.Is(err, context.Canceled) || calls != 0 || sent.Len() != 0 {
			t.Fatalf("pre-canceled operation returned %v, calls=%d, wrote=%q", err, calls, sent.String())
		}
	})
	t.Run("CallbackErrorDoesNotReadReply", func(t *testing.T) {
		p, sent := newTestConn("250 OK\r\n")
		wantErr := errors.New("test hook failure")
		calls := 0
		_, err := commanderFor(t, p).CommandContextAfterFlush(context.Background(), "GETINFO version", func(time.Time) error {
			calls++
			return wantErr
		})
		if !errors.Is(err, wantErr) || calls != 1 || sent.String() != "GETINFO version\r\n" || p.r.Buffered() != 0 {
			t.Fatalf("callback failure returned %v, calls=%d, wire=%q, buffered reply=%d", err, calls, sent.String(), p.r.Buffered())
		}
	})
	t.Run("LiveCallbackErrorDiscardsSession", func(t *testing.T) {
		cfg := t210Fixture(t, "blocked-read")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		p, err := Connect(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		wantErr := errors.New("test hook failure")
		_, err = commanderFor(t, p).CommandContextAfterFlush(ctx, "GETINFO version", func(time.Time) error {
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("callback failure = %v, want wrapped hook error", err)
		}
		if p.cmd.ProcessState == nil {
			t.Fatal("callback failure left the control process unreaped")
		}
	})
	t.Run("LiveHookRunsInsideSessionOperation", func(t *testing.T) {
		cfg := t210Fixture(t, "control")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		p, err := Connect(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		calls := 0
		lines, err := commanderFor(t, p).CommandContextAfterFlush(ctx, "GETINFO version", func(at time.Time) error {
			calls++
			if at.IsZero() {
				t.Error("live post-flush hook received zero timestamp")
			}
			return nil
		})
		if err != nil || strings.Join(lines, "\x00") != "OK" || calls != 1 {
			t.Fatalf("live post-flush command = %q, %v, hook calls=%d", lines, err, calls)
		}
	})
	t.Run("NilHookAndExistingAPIs", func(t *testing.T) {
		p, sent := newTestConn("250 OK\r\n250 OK\r\n")
		if lines, err := p.CommandContext(context.Background(), "GETINFO version"); err != nil || strings.Join(lines, "\x00") != "OK" {
			t.Fatalf("CommandContext compatibility = %q, %v", lines, err)
		}
		if lines, err := p.Command("GETINFO version"); err != nil || strings.Join(lines, "\x00") != "OK" {
			t.Fatalf("Command compatibility = %q, %v", lines, err)
		}
		if got := sent.String(); got != "GETINFO version\r\nGETINFO version\r\n" {
			t.Fatalf("existing API wire bytes = %q", got)
		}
	})
}

type controlFailWriter struct{}

func (controlFailWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic flush failure") }

type controlReadProbe struct {
	reader  io.Reader
	started bool
}

func (p *controlReadProbe) Read(b []byte) (int, error) {
	p.started = true
	return p.reader.Read(b)
}

func commanderFor(t *testing.T, p *ControlPort) postFlushCommander {
	t.Helper()
	commander, ok := any(p).(postFlushCommander)
	if !ok {
		t.Fatal("ControlPort does not implement CommandContextAfterFlush")
	}
	return commander
}

func TestControlSessionUsesTorPrivateUnixSocket(t *testing.T) {
	tmp := t.TempDir()
	argsPath := filepath.Join(tmp, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$STARGATE_T162_ARGV\"\n"
	if err := os.WriteFile(filepath.Join(tmp, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("STARGATE_T162_ARGV", argsPath)
	cfg := ControlPortConfig{Project: "fixture", ComposeFile: "/tmp/compose.yml", EnvFile: "/tmp/local.env"}
	p, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(strings.Fields(string(data)), " ")
	if !strings.Contains(got, "exec -T tor nc -U /var/lib/tor/control/tor-control.sock") {
		t.Fatalf("control transport = %q, want private Tor-only Unix socket", got)
	}
	if strings.Contains(got, "9051") {
		t.Fatalf("control transport retains TCP endpoint: %q", got)
	}
}

// TestParseReplyShapes covers the reply grammar (control-spec §2.3) the
// helper must parse: final, continuation, data block (incl. dot-stuffing
// and the empty block), with `250 OK` payload parity across shapes.
func TestParseReplyShapes(t *testing.T) {
	t.Run("SingleLine250", func(t *testing.T) {
		p, _ := newTestConn("250 ControlPort=0.0.0.0:9051\r\n")
		got, err := p.readReply()
		if err != nil {
			t.Fatalf("readReply: %v", err)
		}
		want := []string{"ControlPort=0.0.0.0:9051"}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("payload lines = %q, want %q", got, want)
		}
	})

	t.Run("ContinuationLines", func(t *testing.T) {
		p, _ := newTestConn("250-K1=v1\r\n250-K2=v2\r\n250 OK\r\n")
		got, err := p.readReply()
		if err != nil {
			t.Fatalf("readReply: %v", err)
		}
		want := []string{"K1=v1", "K2=v2", "OK"}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("payload lines = %q, want %q", got, want)
		}
	})

	t.Run("DataBlockWithDotStuffing", func(t *testing.T) {
		// circuit-status shape: `250+K=` then raw data lines, one per
		// circuit, then the "." terminator. A data line that BEGINS with
		// "." arrives dot-stuffed ("..") and must be un-stuffed to ".".
		replies := "250+circuit-status=\r\n" +
			"$AFB1 BUILT PURPOSE=GENERAL\r\n" +
			"..leading-dot-is-literal\r\n" +
			".\r\n" +
			"250 OK\r\n"
		p, _ := newTestConn(replies)
		got, err := p.readReply()
		if err != nil {
			t.Fatalf("readReply: %v", err)
		}
		want := []string{"circuit-status=", "$AFB1 BUILT PURPOSE=GENERAL", ".leading-dot-is-literal", "OK"}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("payload lines = %q, want %q", got, want)
		}
	})

	t.Run("EmptyDataBlock", func(t *testing.T) {
		// A just-bootstrapped sidecar can report zero circuits: `250+K=`
		// immediately followed by the terminator must parse to zero data
		// lines, not hang and not error.
		p, _ := newTestConn("250+circuit-status=\r\n.\r\n250 OK\r\n")
		got, err := p.readReply()
		if err != nil {
			t.Fatalf("readReply: %v", err)
		}
		want := []string{"circuit-status=", "OK"}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("payload lines = %q, want %q", got, want)
		}
	})

	t.Run("TerminatorOnlyWhenLineExactlyDot", func(t *testing.T) {
		// ".." is a literal "." data line, NOT the terminator — the block
		// must continue past it and terminate on the bare ".".
		replies := "250+x=\r\n..\r\nstill-inside\r\n.\r\n250 OK\r\n"
		p, _ := newTestConn(replies)
		got, err := p.readReply()
		if err != nil {
			t.Fatalf("readReply: %v", err)
		}
		want := []string{"x=", ".", "still-inside", "OK"}
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("payload lines = %q, want %q", got, want)
		}
	})
}

// TestParseReplyRejects covers the external-input discipline (M4): malformed
// lines, error statuses, and bound violations fail with named errors — never
// a silent empty success.
func TestParseReplyRejects(t *testing.T) {
	cases := []struct {
		name    string
		replies string
		wantErr string
	}{
		{"ErrorStatus551", "551 Nothing known\r\n", "551"},
		{"ErrorStatus513", "513 Bad command\r\n", "513"},
		{"MalformedShortLine", "250\r\n", "malformed"},
		{"MalformedNonDigitStatus", "x50 junk\r\n", "malformed"},
		{"MalformedSeparator", "250#weird\r\n", "separator"},
		{"EOFMidReply", "250-K=\r\n", "closed mid-reply"},
		{"LineOverBound", "250 " + strings.Repeat("x", maxLineBytes+1) + "\r\n", "line exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newTestConn(tc.replies)
			got, err := p.readReply()
			if err == nil {
				t.Fatalf("readReply succeeded with %q; want error containing %q", got, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}

	t.Run("ReplyOverTotalBound", func(t *testing.T) {
		// Many legal continuation lines that together exceed the total
		// reply bound must stop with a named error (memory-safety at the
		// edge), not buffer the world.
		var replies bytes.Buffer
		line := strings.Repeat("x", 1024)
		for i := 0; i < (maxReplyBytes/1024)+16; i++ {
			replies.WriteString("250-" + line + "\r\n")
		}
		replies.WriteString("250 OK\r\n")
		p, _ := newTestConn(replies.String())
		if _, err := p.readReply(); err == nil || !strings.Contains(err.Error(), "bytes") {
			t.Fatalf("readReply = %q error, want total-size bound error", err)
		}
	})

	t.Run("LineCountOverBound", func(t *testing.T) {
		// Exactly maxReplyLines legal short continuation lines (~115 KiB,
		// far under maxReplyBytes) must trip readReply's line-count guard,
		// not ride under the total-size bound — deleting readReply's
		// line-count check is caught HERE, not only by a size bound this
		// input never reaches (T062 §Acceptance #2f). readDataBlock's twin
		// guard stays as redundant depth behind the shared total-byte
		// bound; this input contains no `+` line, so that block-side guard
		// is not pinned by this case.
		replies := strings.Repeat("250-x\r\n", maxReplyLines) + "250 OK\r\n"
		p, _ := newTestConn(replies)
		got, err := p.readReply()
		if err == nil {
			t.Fatalf("readReply accepted %d continuation lines; want line-count bound error", maxReplyLines)
		}
		if !strings.Contains(err.Error(), "lines") {
			t.Errorf("error %q does not name the line bound", err)
		}
		if got != nil {
			t.Errorf("payloads %q non-nil on bound error", got)
		}
	})
}

// TestCommandFramingAndSecretDiscipline pins the two Command-level
// properties the consumers depend on: requests are CRLF-terminated exactly
// as sent, and error paths NEVER echo the command text — which is what keeps
// the AUTHENTICATE hex (M5) out of test logs and failure messages.
func TestCommandFramingAndSecretDiscipline(t *testing.T) {
	cookie := []byte("\xde\xad\xbe\xef\x01\x02") // non-hex bytes → hex distinct
	cookieHex := hex.EncodeToString(cookie)

	t.Run("AuthenticateSuccessAndFraming", func(t *testing.T) {
		p, sent := newTestConn("250 OK\r\n")
		if err := p.Authenticate(cookie); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if got := sent.String(); got != "AUTHENTICATE "+cookieHex+"\r\n" {
			t.Fatalf("wire bytes = %q, want AUTHENTICATE with lowercase hex + CRLF", got)
		}
	})

	t.Run("AuthenticateFailureNamesStatusNotSecret", func(t *testing.T) {
		p, _ := newTestConn("550 Failed to authenticate cookie\r\n")
		err := p.Authenticate(cookie)
		if err == nil {
			t.Fatal("Authenticate succeeded against a 550 reply; want error")
		}
		if !strings.Contains(err.Error(), "550") {
			t.Errorf("error %q does not name the status", err)
		}
		if strings.Contains(err.Error(), cookieHex) {
			t.Errorf("error %q leaks the cookie hex — M5 violation (diagnostics carry statuses, never secrets)", err)
		}
	})

	t.Run("CommandErrorDoesNotEchoCommand", func(t *testing.T) {
		p, _ := newTestConn("510 Unrecognized command\r\n")
		_, err := p.Command("SETEVENTS NOTICE") // plausible harness command
		if err == nil {
			t.Fatal("Command succeeded against a 510 reply; want error")
		}
		if strings.Contains(err.Error(), "SETEVENTS") {
			t.Errorf("error %q echoes the command text — must carry status only (M5)", err)
		}
	})

	t.Run("CommandRejectsEmbeddedLineBreak", func(t *testing.T) {
		p, sent := newTestConn("")
		if _, err := p.Command("GETINFO version\r\nINJECT"); err == nil {
			t.Fatal("Command accepted an embedded CRLF; want error (protocol desync guard)")
		}
		if sent.Len() != 0 {
			t.Errorf("rejected command still wrote %q to the wire", sent.String())
		}
	})

	t.Run("EmptyCookieRejected", func(t *testing.T) {
		p, sent := newTestConn("250 OK\r\n")
		if err := p.Authenticate(nil); err == nil {
			t.Fatal("Authenticate(nil) succeeded; want loud failure (M1: never authenticate 'something')")
		}
		if sent.Len() != 0 {
			t.Errorf("empty cookie still wrote %q to the wire", sent.String())
		}
	})
}

// TestCloseOnSessionlessConn guards the deferred-cleanup path: Close on a
// test-wired conn (no exec process) is a no-op, never a nil panic.
func TestCloseOnSessionlessConn(t *testing.T) {
	p, _ := newTestConn("")
	p.stdin = nil
	p.cmd = nil
	if err := p.Close(); err != nil {
		t.Fatalf("Close on sessionless conn: %v", err)
	}
	var nilP *ControlPort
	if err := nilP.Close(); err != nil {
		t.Fatalf("Close on nil conn: %v", err)
	}
}

// T210 challenges the real subprocess transport; synthetic diagnostics contain no
// cookie, command, destination or production state (Constitution VII).
const t210Transport = `#!/usr/bin/python3 -B
import os,sys,time,threading,subprocess
mode=os.environ.get("T210_MODE", "control")
if mode == "held-descriptor":
 child=subprocess.Popen([sys.executable,"-B","-c","import time;time.sleep(30)"])
 open(os.environ["T210_CHILD_PID"],"w").write(str(child.pid))
 os._exit(0)
if mode == "blocked-write":
 open(os.environ["T210_READY"],"w").write("ready")
 time.sleep(30)
 sys.exit(0)
def diagnostics():
 end=time.monotonic()+1
 while time.monotonic()<end:
  os.write(2,b"synthetic transport diagnostic\n"*128)
def eof():
 thread=threading.Thread(target=diagnostics)
 thread.start()
 os.close(1)
 thread.join()
for line in sys.stdin.buffer:
 if line.startswith(b"QUIT"):
  sys.exit(0)
 if mode == "blocked-read":
  time.sleep(30)
  sys.exit(0)
 if line.startswith(b"EOF"):
  eof()
  sys.exit(0)
 os.write(1,b"250 OK\r\n")
`

func t210Fixture(t *testing.T, mode string) ControlPortConfig {
	t.Helper()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "docker"), []byte(t210Transport), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("T210_MODE", mode)
	t.Setenv("T210_READY", filepath.Join(tmp, "ready"))
	t.Setenv("T210_CHILD_PID", filepath.Join(tmp, "child-pid"))
	return ControlPortConfig{Project: "t210-fixture", ComposeFile: "/fixture/compose.yml", EnvFile: "/fixture/local.env"}
}

func t210Command(ctx context.Context, p *ControlPort, command string) ([]string, error) {
	// Compile and exercise the old exported API before the additive operation
	// exists, so RED demonstrates missing cancellation rather than missing code.
	if c, ok := any(p).(interface {
		CommandContext(context.Context, string) ([]string, error)
	}); ok {
		return c.CommandContext(ctx, command)
	}
	return p.Command(command)
}

func t210Kill(t *testing.T, p *ControlPort) {
	t.Helper()
	if p != nil && p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	if p != nil && p.stdin != nil {
		_ = p.stdin.Close()
	}
}

func TestT210ControlDiagnostics(t *testing.T) {
	cfg := t210Fixture(t, "control")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Authenticate([]byte("synthetic-cookie")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Command("GETINFO version"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		if _, err := p.Command("EOF"); err == nil {
			t.Fatal("EOF transport returned success")
		}
	}
}

func TestT210ControlOperationBounds(t *testing.T) {
	for _, mode := range []string{"blocked-read", "blocked-write"} {
		t.Run(mode, func(t *testing.T) {
			cfg := t210Fixture(t, mode)
			lifetime, cancelLifetime := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelLifetime()
			p, err := Connect(lifetime, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			op, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			command := "GETINFO version"
			if mode == "blocked-write" {
				command = strings.Repeat("x", 1<<20)
			}
			done := make(chan error, 1)
			go func() { _, err := t210Command(op, p, command); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("blocked operation returned success")
				}
			case <-time.After(700 * time.Millisecond):
				t210Kill(t, p)
				<-done
				t.Error("operation ignored its 100ms deadline at actual pipe I/O")
			}
		})
	}
	t.Run("AlreadyCancelled", func(t *testing.T) {
		cfg := t210Fixture(t, "control")
		p, err := Connect(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		op, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := t210Command(op, p, "GETINFO version"); err == nil {
			t.Fatal("cancelled operation was admitted")
		}
	})
	t.Run("SuccessfulOperationRetainsSession", func(t *testing.T) {
		cfg := t210Fixture(t, "control")
		p, err := Connect(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		op, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err = t210Command(op, p, "GETINFO version")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Command("GETINFO version"); err != nil {
			t.Fatalf("successful phase cancellation killed reusable session: %v", err)
		}
	})
}

func TestT210ControlCloseBounds(t *testing.T) {
	t.Run("TimerPrecedesFlush", func(t *testing.T) {
		cfg := t210Fixture(t, "blocked-write")
		p, err := Connect(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { t210Kill(t, p); _ = p.Close() }()
		deadline := time.Now().Add(time.Second)
		for {
			if _, err := os.Stat(os.Getenv("T210_READY")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("child never ready")
			}
			time.Sleep(time.Millisecond)
		}
		f := p.stdin.(*os.File)
		fd := int(f.Fd())
		if err := syscall.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
		for {
			_, err := syscall.Write(fd, make([]byte, 4096))
			if errors.Is(err, syscall.EAGAIN) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := syscall.SetNonblock(fd, false); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		start := time.Now()
		go func() { done <- p.Close() }()
		select {
		case <-done:
			if time.Since(start) > 5500*time.Millisecond {
				t.Error("Close exceeded its existing 5s teardown plus scheduling allowance")
			}
		case <-time.After(6 * time.Second):
			t210Kill(t, p)
			<-done
			t.Error("Close blocked before arming its 5s timer")
		}
	})
	t.Run("InheritedDiagnosticDescriptor", func(t *testing.T) {
		cfg := t210Fixture(t, "held-descriptor")
		p, err := Connect(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		childPath := os.Getenv("T210_CHILD_PID")
		deadline := time.Now().Add(time.Second)
		var child int
		for {
			raw, err := os.ReadFile(childPath)
			if err == nil {
				_, _ = fmt.Sscanf(string(raw), "%d", &child)
				if child > 0 {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("child identity absent")
			}
			time.Sleep(time.Millisecond)
		}
		t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
		done := make(chan error, 1)
		go func() { done <- p.Close() }()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			_ = syscall.Kill(child, syscall.SIGKILL)
			<-done
			t.Error("Wait remained blocked on an inherited diagnostic descriptor")
		}
		if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child)); err == nil && !strings.Contains(string(raw), ") Z ") {
			t.Error("owned descriptor-holding child survived Close")
		}
	})
}

// Pin the selected test executable's prerequisite without contacting Docker.
func TestT210FixtureTool(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal(err)
	}
}
