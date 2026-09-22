// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package errortpl holds the privacy-safe error-response template literal
// for the future HTTP renderer; Tor port 8881 never emits it (architecture spec
// §10.2; specs/001-tor-route/contracts/error-template.md §"Response body").
//
// This file holds the LITERAL ONLY — the bytes the renderer (T048 / T071)
// substitutes {ROUTE_LABEL}, {CODE}, and {LOCAL_REFERENCE_ID} into. The
// bytes are pinned byte-for-byte against the contract; the unit test
// (template_test.go) gates against silent drift from a Windows edit (CRLF
// contamination), a typo'd placeholder token, or a middle-dot look-alike
// substitution.
package errortpl

// Template is the future-format error-response body for direct renderer calls (ROUTE_DOWN / ROUTE_REFUSED / ROUTE_TIMEOUT /
// AUTH_REQUIRED). The bytes are byte-for-byte equal to the code-block
// content of specs/001-tor-route/contracts/error-template.md §"Response
// body" — no trailing newline, LF line endings, UTF-8 middle-dot `·`
// (U+00B7, bytes 0xC2 0xB7).
//
// Permitted substitutions (handled by the renderer in T048 / T071, NOT
// here):
//
//   - {ROUTE_LABEL}       — fixed vocabulary: "Tor", "I2P", "Mixnet", "Direct".
//   - {CODE}              — one of ROUTE_DOWN / ROUTE_REFUSED / ROUTE_TIMEOUT / AUTH_REQUIRED.
//   - {LOCAL_REFERENCE_ID} — 16-char lowercase-hex of crypto/rand.Read(8);
//     NOT derived from request data (per §"Response body" leak invariant).
//
// The literal is stored as a Go raw string literal (backticks) so future
// editors see whitespace unambiguously in code review; a double-quoted
// string with \n escapes would tempt drive-by escape edits. Go's
// text/template package is NOT used — its syntax is {{...}}, not {...},
// and the renderer is plain strings.ReplaceAll per T048 / T071.
//
// The constant is exported because T048 / T071 import it from outside
// the errortpl package. Lowercase would force them into the same package
// and break separation of concerns.
const Template = `<!doctype html><meta charset=utf-8>
<title>Stargate: route unavailable</title>
<h1>Route unavailable</h1>
<p>The {ROUTE_LABEL} route is currently not serving requests.</p>
<p>Code: {CODE} · Reference: {LOCAL_REFERENCE_ID}</p>
<p>See the admin dashboard for details.</p>`
