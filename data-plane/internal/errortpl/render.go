// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Future HTTP format renderer; no Tor listener ingress uses this package.
package errortpl

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrorCode is the future-format vocabulary, independent of proxy ingress.
type ErrorCode string

const (
	CodeAuthRequired ErrorCode = "AUTH_REQUIRED"
	CodeRouteDown    ErrorCode = "ROUTE_DOWN"
	CodeRouteRefused ErrorCode = "ROUTE_REFUSED"
	CodeRouteTimeout ErrorCode = "ROUTE_TIMEOUT"
)

// Renderer takes no request data. Only its random reference ID varies.
type Renderer struct{}

// authRequiredStatusLine is the contract §"Status line" AUTH_REQUIRED
// row, byte-exact (T027's wantStatusLine pins it from the test side).
const authRequiredStatusLine = "HTTP/1.1 407 Proxy Authentication Required\r\n"

// header lines fixed by contract §"Response headers" — exactly these
// four, in this order, no others (T068a pins order and byte shape).
// Assembled by hand, never net/http: Go's default Server/Date/
// Connection headers are contract-forbidden (T068a's forbidden set).
const (
	headerContentType  = "Content-Type: text/html; charset=utf-8\r\n"
	headerCacheControl = "Cache-Control: no-store\r\n"
)

// WriteFailure renders code's response onto w. AUTH_REQUIRED is the
// T048 scope; a route code writes nothing and returns an error —
// T071 owns their atomic tests-first implementation; T173 preserves this boundary.
func (r *Renderer) WriteFailure(w io.Writer, code ErrorCode) error {
	if code != CodeAuthRequired {
		return fmt.Errorf("errortpl: code %q has no renderer yet (T071)", code)
	}

	// The §"Response body" LOCAL_REFERENCE_ID is 16 lowercase hex chars
	// from this 64-bit draw, never from request data (Principle III).
	var refID [8]byte
	if _, err := rand.Read(refID[:]); err != nil {
		return fmt.Errorf("errortpl: generating LOCAL_REFERENCE_ID: %w", err)
	}
	body := strings.NewReplacer(
		"{ROUTE_LABEL}", "Tor",
		"{CODE}", string(CodeAuthRequired),
		"{LOCAL_REFERENCE_ID}", hex.EncodeToString(refID[:]),
	).Replace(Template)

	// Content-Length is the body byte length (T068a (d) gates the
	// equality on the wire); strconv appends plain ASCII digits.
	var buf strings.Builder
	buf.WriteString(authRequiredStatusLine)
	buf.WriteString(headerContentType)
	buf.WriteString("Content-Length: ")
	buf.WriteString(strconv.Itoa(len(body)))
	buf.WriteString("\r\n")
	buf.WriteString(headerCacheControl)
	buf.WriteString("X-Stargate-Error: ")
	buf.WriteString(string(CodeAuthRequired))
	buf.WriteString("\r\n\r\n")
	buf.WriteString(body)

	_, err := io.WriteString(w, buf.String())
	return err
}
