// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package torrc hosts the contract tests for the byte-level invariants of
// the Tor sidecar's image-baked `torrc`. The authoritative template lives in
// specs/001-tor-route/contracts/torrc.md §"Rendered file"; this package
// gates drift between that contract document and the pinned golden, and
// (via T087's cold-volume regression test) between the golden and the
// `/etc/tor/torrc` baked into the Tor image at build time.
//
// Cross-plane split (T029 §Analysis, amended by T089): research.md §5
// rejects a JVM in the Go contract-test path, so a Go test cannot call a
// Java `TorrcRenderer.render()` directly. For v1 the byte-for-byte chain
// is Go-only — the Java renderer is deferred with T037 to the dynamic-
// config feature (T089 bakes the torrc into the image so Tor startup
// never waits for the control plane; Constitution Principle II / sol-
// review B2):
//
//	contracts/torrc.md §"Rendered file"  ==  wantTorrc (this Go const)
//	                    ==  /etc/tor/torrc baked into the image  (T087 cold-volume test)
//
// This file owns the first link: it pins the v1 template as a Go golden
// and cross-checks the contract document against it at run time, so any
// edit to the image-baked template that is not accompanied by a golden
// update fails this test. The image-side link (image /etc/tor/torrc ==
// golden) is T087's scope; T087's cold-volume regression test reads the
// file out of the image without harness-seeded config.
//
// FR-011 (spec.md §"Sidecar configuration", amended by T089) requires this
// byte-for-byte gate; Constitution Principle VII (tests-first for privacy-
// critical contract code) requires it land before the image-baking (T087).
package torrc

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// renderedFileSection is the markdown heading whose fenced block holds the
// authoritative v1 template. Anchoring the fence search to this heading
// (rather than grabbing the first ``` fence in the file) keeps the
// extraction robust against future contract edits that add other fenced
// blocks elsewhere in the document.
const renderedFileSection = "## Rendered file"

// wantTorrc is the byte-exact v1 image-baked torrc, transcribed verbatim
// from specs/001-tor-route/contracts/torrc.md §"Rendered file" (the fenced
// block). It is the golden against which (a) the contract document is
// cross-checked at run time by TestRenderedTorrcByteMatch, and (b) the
// `/etc/tor/torrc` baked into the Tor image is checked by T087's cold-
// volume regression test. Per contracts/torrc.md invariant #13 the file
// ends with a single trailing "\n" and uses LF line endings (no CRLF
// anywhere).
//
// The em-dashes (U+2014) on the "Stargate v1 — Tor" and
// "Logging — Notice" lines are UTF-8 (E2 80 94); Go raw-string literals
// carry them byte-for-byte.
//
// Privacy-load-bearing directives this golden carries (contracts/torrc.md
// invariants flagged for SECURITY-DECISIONS.md review on change):
// IsolateSOCKSAuth (inv. 1), ClientUseIPv6 0 (5), AvoidDiskWrites 1 (6),
// UseBridges 0 + no Bridge lines (7), SafeLogging 1 (8), and no per-user
// data in any comment (12) — all covered transitively by the byte-match.
// DataDirectory /var/lib/tor (inv. 11) is pinned explicitly because the
// image entrypoint does not load Debian's torrc-defaults (T087 / T089).
const wantTorrc = `# Stargate v1 — Tor sidecar configuration.
# Baked into the Tor image at build time. Do not edit by hand.
# Source: specs/001-tor-route/contracts/torrc.md

SocksPort unix:/run/tor-fabric/private/tor-socks.sock IsolateClientAddr IsolateSOCKSAuth
ControlSocket /var/lib/tor/control/tor-control.sock
CookieAuthentication 1
CookieAuthFileGroupReadable 1
DataDirectory /var/lib/tor
ClientUseIPv6 0
AvoidDiskWrites 1
UseBridges 0

# Logging — diagnostics are discarded before retention (Constitution III).
# Current health comes from the authenticated observer, not retained log lines.
Log notice file /dev/null
SafeLogging 1
`

// TestRenderedTorrcByteMatch is the FR-011 byte-for-byte gate on the v1
// image-baked torrc. It extracts the rendered-file code fence from the
// contract document and asserts it equals wantTorrc exactly, so any drift
// between the contract template and the pinned golden fails loudly. It
// also asserts the structural invariants (#13: single trailing LF, no
// CR) on wantTorrc directly — cheap, deterministic, independent of the
// markdown parse.
//
// Per-invariant rows 1–12 are broken out individually in T030
// (invariants_test.go); this test is the whole-file gate. The no-bridges
// substring sweep is T031. The live-sidecar GETCONF assertion is T032.
// The image-side link (image /etc/tor/torrc == golden, without harness-
// seeded config) is T087's cold-volume regression test.
//
// This test does NOT self-skip on a missing Java renderer: under T089's
// amendment the v1 chain is Go-only (the Java TorrcRenderer is deferred
// with T037), so this test pins the contract immediately. It is wired
// into CI by T076; verify.sh does not run the tests/contract Go module
// today (see T029 §Analysis residue), so until T076 lands it is invoked
// manually via `cd tests/contract && go test ./torrc/`.
func TestRenderedTorrcByteMatch(t *testing.T) {
	contractFile := filepath.Join(findRepoRoot(t),
		"specs", "001-tor-route", "contracts", "torrc.md")

	fenceBytes, err := extractRenderedFileFence(contractFile)
	if err != nil {
		t.Fatalf("extracting rendered-file fence from %s: %v — the contract "+
			"document structure changed; update the fence extraction or "+
			"restore the `## Rendered file` fenced block", contractFile, err)
	}

	// (a) Whole-file byte-for-byte equality between the contract document
	// and the pinned golden. Report the first diverging offset so a drift
	// is locatable without dumping the torrc (it is secret-free, but the
	// pointed diff is more useful than a full dump).
	if !bytes.Equal(fenceBytes, []byte(wantTorrc)) {
		t.Errorf("contracts/torrc.md §\"Rendered file\" fence does NOT "+
			"equal the wantTorrc golden byte-for-byte (FR-011 / T029) — "+
			"contract-doc drift not reflected in the golden (or vice "+
			"versa). First diverging byte at offset %d (golden %d bytes, "+
			"fence %d bytes). Update both in lock-step per "+
			"contracts/torrc.md §\"When this contract changes\".",
			firstDifferingOffset(fenceBytes, []byte(wantTorrc)),
			len(wantTorrc), len(fenceBytes))
	}

	// (b) Structural invariants (#13) on the golden itself: exactly one
	// trailing LF, and no CR anywhere. Independent of the markdown parse
	// above, so a fence-extraction regression cannot mask a newline
	// defect.
	if !strings.HasSuffix(wantTorrc, "\n") {
		t.Errorf("wantTorrc golden does not end with a trailing \\n — " +
			"contracts/torrc.md invariant #13 requires a single trailing " +
			"newline (no missing newline at EOF)")
	}
	if strings.HasSuffix(wantTorrc, "\n\n") {
		t.Errorf("wantTorrc golden ends with two+ newlines — " +
			"contracts/torrc.md invariant #13 requires exactly ONE " +
			"trailing newline")
	}
	if strings.ContainsRune(wantTorrc, '\r') {
		t.Errorf("wantTorrc golden contains a CR (\\r) — " +
			"contracts/torrc.md invariant #13 forbids CRLF; line " +
			"endings must be LF only")
	}
}

// extractRenderedFileFence reads contractFile, locates the
// `## Rendered file` section, and returns the bytes inside the first
// fenced code block that follows it (the content between the opening
// "```\n" and the closing "\n```", including the trailing newline before
// the closing fence). Returns an error if the section header or the
// fenced block cannot be found.
func extractRenderedFileFence(contractFile string) ([]byte, error) {
	raw, err := os.ReadFile(contractFile)
	if err != nil {
		return nil, err
	}
	secIdx := bytes.Index(raw, []byte(renderedFileSection))
	if secIdx < 0 {
		return nil, fmt.Errorf("section header %q not found", renderedFileSection)
	}
	openRel := bytes.Index(raw[secIdx:], []byte("```\n"))
	if openRel < 0 {
		return nil, fmt.Errorf("opening ``` fence after %q not found", renderedFileSection)
	}
	contentStart := secIdx + openRel + len("```\n")
	closeRel := bytes.Index(raw[contentStart:], []byte("\n```"))
	if closeRel < 0 {
		return nil, fmt.Errorf("closing ``` fence after %q not found", renderedFileSection)
	}
	// Include the "\n" that precedes the closing fence so the returned
	// content ends with the single trailing newline invariant #13 pins.
	return raw[contentStart : contentStart+closeRel+1], nil
}

// firstDifferingOffset returns the index of the first byte at which a and
// b differ, or min(len(a),len(b)) if one is a prefix of the other. Used
// to make the byte-match failure message locatable without a full dump.
func firstDifferingOffset(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// findRepoRoot walks up from this test file's source location to find the
// directory containing specs/001-tor-route/contracts/torrc.md — the
// contract file the test cross-checks. Locating the root via the contract
// path itself (rather than the compose marker used in
// tests/contract/tor/) keeps this test's dependency to exactly the file
// it consumes. Mirrors the runtime.Caller walk pattern of findRepoRoot in
// tests/contract/tor/port_exposure_test.go (T019b); not importable across
// packages, so re-implemented here.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate test source path")
	}
	dir := filepath.Dir(thisFile)
	rel := filepath.Join("specs", "001-tor-route", "contracts", "torrc.md")
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("repo root (containing " + rel + ") not found by walking up " +
		"from " + filepath.Dir(thisFile))
	return ""
}
