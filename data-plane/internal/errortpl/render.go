// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// render.go — the AUTH_REQUIRED wire renderer (T048): assembles the
// privacy-safe error response for the HTTP CONNECT auth-failure case
// from the byte-pinned Template literal (T019). The wire shape is
// contracts/error-template.md §"Wire format" — status line
// `HTTP/1.1 407 Proxy Authentication Required`, exactly the four
// contract headers in declared order, then the body with the three
// permitted substitutions. ROUTE_DOWN/ROUTE_REFUSED/ROUTE_TIMEOUT are
// deliberately NOT rendered here: their status rows are T071's
// extension of this file, and inventing them now would redefine a wire
// shape outside the contract-review loop (T048 §Analysis scope split).
package errortpl

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/zcat-app/stargate/data-plane/internal/listener"
)

// Renderer renders error responses onto the wire. It satisfies
// listener.ErrorRenderer and is stateless: every response is assembled
// from the constants below plus one fresh random ref-ID, so nothing
// request-derived can enter the bytes (FR-006/FR-009; the only variable
// bytes are the ref-ID slot and the Content-Length digits it implies).
//
// Compile-time seam conformance: T050 fills listener.ConnectDeps.
// Renderer with this type.
var _ listener.ErrorRenderer = (*Renderer)(nil)

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

// refIDLen is the §"Response body" LOCAL_REFERENCE_ID: 16 lowercase hex
// chars from a 64-bit crypto/rand draw — never derived from request
// data (not the token, destination, timestamp, or source port).
const refIDLen = 16

// WriteFailure renders code's response onto w. AUTH_REQUIRED is the
// T048 scope; a route code writes nothing and returns an error —
// HandleConnect treats renderer errors as best-effort (the connection
// closes silently), and T071 lifts the route rows in this same file.
func (r *Renderer) WriteFailure(w io.Writer, code listener.ErrorCode) error {
	if code != listener.CodeAuthRequired {
		return fmt.Errorf("errortpl: code %q has no renderer yet (T071)", code)
	}

	var refID [8]byte
	if _, err := rand.Read(refID[:]); err != nil {
		return fmt.Errorf("errortpl: generating LOCAL_REFERENCE_ID: %w", err)
	}
	body := strings.NewReplacer(
		"{ROUTE_LABEL}", "Tor",
		"{CODE}", string(listener.CodeAuthRequired),
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
	buf.WriteString(string(listener.CodeAuthRequired))
	buf.WriteString("\r\n\r\n")
	buf.WriteString(body)

	_, err := io.WriteString(w, buf.String())
	return err
}
