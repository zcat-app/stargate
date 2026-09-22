// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Direct renderer contract: exact AUTH_REQUIRED format, no variation outside
// its reference-ID slot and full response leak scans. T173 removes all ingress
// claims; actual credential refusal remains in the SOCKS/refusal suites.
package errortemplate

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

const authRequiredPlaintext = "a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c"
const malformedToken = "notatoken"
const wantStatusLine = "HTTP/1.1 407 Proxy Authentication Required\r\n"
const wantXStargateError = "X-Stargate-Error: AUTH_REQUIRED\r\n"
const refIDSlotPrefix = "Code: AUTH_REQUIRED · Reference: "
const refIDHexLen = 16

// authRequiredBodyRe matches the AUTH_REQUIRED response body
// byte-for-byte, with {ROUTE_LABEL}="Tor", {CODE}="AUTH_REQUIRED",
// and {LOCAL_REFERENCE_ID}=[0-9a-f]{16}. Synced from
// contracts/error-template.md §"Response body" at /start 2026-07-07
// (which matches data-plane/internal/errortpl/template.go's Template
// literal byte-for-byte per T019's gate). The contract file is the
// durable source of truth; this inline copy is the gate that catches
// drift between the contract and the DP's rendered body.
//
// LF line endings (single \n), NOT CRLF — per §"Response body":
// "Line endings are \n (single LF), not CRLF". Anchored with ^...$
// so an extra body element before or after the Template fails the
// match (§Analysis redteam scope (e)). The · is the UTF-8 middle dot
// (U+00B7, bytes 0xC2 0xB7) — Go regexp handles UTF-8 natively.
var authRequiredBodyRe = regexp.MustCompile(
	`^<!doctype html><meta charset=utf-8>\n` +
		`<title>Stargate: route unavailable</title>\n` +
		`<h1>Route unavailable</h1>\n` +
		`<p>The Tor route is currently not serving requests\.</p>\n` +
		`<p>Code: AUTH_REQUIRED · Reference: [0-9a-f]{16}</p>\n` +
		`<p>See the admin dashboard for details\.</p>$`)

var rendererBuild sync.Once
var rendererBinary string
var rendererBuildError error
var rendererBuildOutput []byte

// Build errors fail the suite; missing source cannot silently become a skip.
func renderCode(t *testing.T, code string) ([]byte, error) {
	t.Helper()
	rendererBuild.Do(func() {
		root := dpharness.FindRepoRoot(t)
		rendererBinary = filepath.Join(root, "target", "t173-renderer-fixture")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", rendererBinary, "./internal/errortpl/testdata/render")
		cmd.Dir = filepath.Join(root, "data-plane")
		rendererBuildOutput, rendererBuildError = cmd.CombinedOutput()
	})
	if rendererBuildError != nil {
		t.Fatalf("renderer fixture build: %v: %s", rendererBuildError, rendererBuildOutput)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, rendererBinary, code).Output()
}

func TestAUTHRequired(t *testing.T) {
	first, err := renderCode(t, "AUTH_REQUIRED")
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderCode(t, "AUTH_REQUIRED")
	if err != nil {
		t.Fatal(err)
	}
	for i, resp := range [][]byte{first, second} {
		assertStatusShape(t, "direct renderer", resp)
		assertBodyTemplate(t, "direct renderer", resp)
		loginvariants.AssertNoSecrets(t, string(resp), []byte("t027-dest.example.onion"), []byte(malformedToken), []byte(authRequiredPlaintext))
		if i == 1 && bytes.Equal(first, resp) {
			t.Error("reference ID was reused")
		}
	}
	if !bytes.Equal(maskRefIDSlot(t, first), maskRefIDSlot(t, second)) {
		t.Error("renderer differs outside permitted reference-ID slot")
	}
}

// assertStatusShape asserts resp begins with the AUTH_REQUIRED
// status line and carries the X-Stargate-Error: AUTH_REQUIRED
// header. Gates the response IS the AUTH_REQUIRED template before
// the structural-equality check gives a misleading byte-comparison
// failure. Response bytes are WITHHELD from the failure message (a
// buggy DP may echo the destination or malformed token into the
// response; those are scanned separately under
// Response_NoCorpusItem).
func assertStatusShape(t *testing.T, label string, resp []byte) {
	t.Helper()
	if !bytes.HasPrefix(resp, []byte(wantStatusLine)) {
		t.Errorf("%s: AUTH_REQUIRED response does not start "+
			"with the contract status line (contracts/error-"+
			"template.md §\"Wire format · Status line\", "+
			"AUTH_REQUIRED row); got %d bytes (withheld; see "+
			"Response_NoCorpusItem_%s for the dest/token scan)",
			label, len(resp), label)
		return
	}
	if !bytes.Contains(resp, []byte(wantXStargateError)) {
		t.Errorf("%s: AUTH_REQUIRED response missing the "+
			"X-Stargate-Error: AUTH_REQUIRED header "+
			"(contracts/error-template.md §\"Wire format · "+
			"Response headers\"); got %d bytes (withheld)",
			label, len(resp))
	}
}

// assertBodyTemplate asserts the response body matches the errortpl
// Template literal byte-for-byte after substituting
// {ROUTE_LABEL}="Tor", {CODE}="AUTH_REQUIRED", and
// {LOCAL_REFERENCE_ID}=a 16-char lowercase-hex run. Locates the body
// via the header-terminating blank line (\r\n\r\n); LF line endings
// in the body per §"Response body". A DP that emits a different body
// (extra whitespace, missing element, wrong ROUTE_LABEL, trailing
// newline, CRLF contamination) fails here. The match is
// full-Template-literal (anchored ^...$), not prefix/suffix
// (§Analysis redteam scope (e)).
func assertBodyTemplate(t *testing.T, label string, resp []byte) {
	t.Helper()
	body := bodyAfterHeaders(resp)
	if body == nil {
		t.Errorf("%s: AUTH_REQUIRED response has no header-"+
			"terminating blank line (\\r\\n\\r\\n) — the header "+
			"block is malformed or never terminated "+
			"(contracts/error-template.md §\"Wire format\"); "+
			"got %d bytes (withheld)", label, len(resp))
		return
	}
	if !authRequiredBodyRe.Match(body) {
		t.Errorf("%s: AUTH_REQUIRED body does not match the "+
			"Template literal with {ROUTE_LABEL}=\"Tor\", "+
			"{CODE}=\"AUTH_REQUIRED\", {LOCAL_REFERENCE_ID}="+
			"[0-9a-f]{16} (contracts/error-template.md "+
			"§\"Response body\"); body was %d bytes (withheld; "+
			"see Response_NoCorpusItem_%s for the dest/token "+
			"scan)", label, len(body), label)
	}
}

// bodyAfterHeaders returns the bytes after the header-terminating
// blank line (\r\n\r\n), or nil if the blank line is absent. The
// body starts immediately after the 4-byte terminator.
func bodyAfterHeaders(resp []byte) []byte {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil
	}
	return resp[idx+4:]
}

// maskRefIDSlot returns a copy of resp with the 16-byte
// LOCAL_REFERENCE_ID slot (the bytes immediately following
// refIDSlotPrefix) zeroed out. Fails the test if the prefix is
// absent or the response ends before 16 bytes follow it — the
// slot's location is load-bearing for the structural-equality check,
// and a DP that moves or removes it breaches the body-template
// contract (BodyTemplate would have flagged the shape failure first;
// reaching this point with a missing slot is a divergent bug worth
// surfacing explicitly).
func maskRefIDSlot(t *testing.T, resp []byte) []byte {
	t.Helper()
	prefix := []byte(refIDSlotPrefix)
	idx := bytes.Index(resp, prefix)
	if idx < 0 {
		t.Fatalf("AUTH_REQUIRED response missing the ref-ID slot "+
			"prefix %q — the body does not match contracts/error-"+
			"template.md §\"Response body\" (BodyTemplate would "+
			"have flagged this first; response bytes withheld)",
			refIDSlotPrefix)
	}
	slotStart := idx + len(prefix)
	slotEnd := slotStart + refIDHexLen
	if slotEnd > len(resp) {
		t.Fatalf("AUTH_REQUIRED response ends %d bytes after the "+
			"ref-ID slot prefix, want at least %d (a 16-hex "+
			"ref-ID) — truncated response (bytes withheld)",
			len(resp)-slotStart, refIDHexLen)
	}
	out := make([]byte, len(resp))
	copy(out, resp)
	for i := slotStart; i < slotEnd; i++ {
		out[i] = 0
	}
	return out
}
