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
	"encoding/hex"
	"strings"
	"testing"
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
