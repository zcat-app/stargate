// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package errortpl

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// expectedTemplate is the byte-exact expected content of Template,
// hand-synced from specs/001-tor-route/contracts/error-template.md
// §"Response body" at /start 2026-07-05 against HEAD d5e9b9c. The contract
// file is the durable source of truth; this inline copy is the gate that
// catches silent drift between the contract and the Go constant. A future
// contract edit without a corresponding edit here fails ByteExactMatch.
//
// Trailing newline: NONE. The contract's code-block closing ``` on a
// separate line is markdown syntax, not template content. See ticket
// §Residue "Trailing newline" item.
var expectedTemplate = []byte(
	"<!doctype html><meta charset=utf-8>\n" +
		"<title>Stargate: route unavailable</title>\n" +
		"<h1>Route unavailable</h1>\n" +
		"<p>The {ROUTE_LABEL} route is currently not serving requests.</p>\n" +
		"<p>Code: {CODE} · Reference: {LOCAL_REFERENCE_ID}</p>\n" +
		"<p>See the admin dashboard for details.</p>",
)

// placeholderTokenRe matches `{TOKEN_NAME}` style substitution slots. The
// renderer (T048 / T071) substitutes the three permitted tokens; any
// OTHER `{...}` sequence in Template would either be a typo or an
// unrelated literal brace the renderer does not know about.
var placeholderTokenRe = regexp.MustCompile(`\{[A-Z_]+\}`)

func TestTemplateLiteral(t *testing.T) {
	t.Run("ByteExactMatch", func(t *testing.T) {
		got := []byte(Template)
		if !bytes.Equal(got, expectedTemplate) {
			t.Errorf("Template bytes diverge from expectedTemplate\n"+
				"  got len=%d:  %q\n"+
				"  want len=%d: %q",
				len(got), got, len(expectedTemplate), expectedTemplate)
		}
	})

	t.Run("OnlyPermittedPlaceholderTokens", func(t *testing.T) {
		matches := placeholderTokenRe.FindAllString(Template, -1)
		want := []string{"{ROUTE_LABEL}", "{CODE}", "{LOCAL_REFERENCE_ID}"}
		if len(matches) != len(want) {
			t.Fatalf("expected %d placeholder tokens, got %d: %v", len(want), len(matches), matches)
		}
		// Order does NOT matter: the renderer substitutes by token
		// name, so a permutation would still render correctly. Assert
		// as sets to permit future contract edits that reorder tokens
		// without changing semantics.
		gotSet := make(map[string]struct{}, len(matches))
		for _, m := range matches {
			gotSet[m] = struct{}{}
		}
		wantSet := make(map[string]struct{}, len(want))
		for _, w := range want {
			wantSet[w] = struct{}{}
		}
		for tok := range wantSet {
			if _, ok := gotSet[tok]; !ok {
				t.Errorf("permitted placeholder %s missing from Template", tok)
			}
		}
		for tok := range gotSet {
			if _, ok := wantSet[tok]; !ok {
				t.Errorf("forbidden placeholder %s present in Template — only {ROUTE_LABEL}, {CODE}, {LOCAL_REFERENCE_ID} are permitted", tok)
			}
		}
	})

	t.Run("LFOnlyLineEndings", func(t *testing.T) {
		// CRLF contamination from a Windows edit would silently change
		// the wire-format byte count and break the leak-corpus scan at
		// the renderer layer. Gate it here.
		if i := strings.IndexByte(Template, '\r'); i >= 0 {
			t.Errorf("Template contains CR at byte offset %d — LF-only line endings required (CRLF would corrupt the wire-format byte count)", i)
		}
	})

	t.Run("MiddleDotPreserved", func(t *testing.T) {
		// UTF-8 middle-dot · is U+00B7 = bytes 0xC2 0xB7. Common
		// editor "autocorrect" substitutes include bullet • (U+2022 =
		// 0xE2 0x80 0xA2) and Greek ano teleia · (U+0387 = 0xCD 0xB7).
		// Each would change the byte length and break byte-exact wire
		// format. Assert the literal UTF-8 bytes appear exactly once.
		middleDot := []byte{0xc2, 0xb7}
		count := bytes.Count([]byte(Template), middleDot)
		if count != 1 {
			t.Errorf("Template must contain exactly one UTF-8 middle-dot (U+00B7 = bytes 0xC2 0xB7); got %d occurrences. A common cause is editor autocorrect swapping · for • (U+2022) or · (U+0387).", count)
		}
	})

	t.Run("NoTrailingNewline", func(t *testing.T) {
		// The contract code block's closing ``` on a separate line is
		// markdown syntax, not template content. The literal ends with
		// `</p>`, NOT `</p>\n`. See ticket §Residue "Trailing newline"
		// for the contract-ambiguity rationale.
		if strings.HasSuffix(Template, "\n") {
			t.Errorf("Template must not end with a trailing newline — got %q (last 8 bytes)", []byte(Template)[len(Template)-8:])
		}
	})
}
