---
id: T019
title: 'Author the privacy-safe error template literal'
status: done
created: 2026-07-04
last_updated: 2026-07-06
source: tasks.md#T019
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]
parallel: false
files_budget: 8
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/error-template.md §"Response body"
  - specs/000-architecture/spec.md §10.2
decision_refs:
  - specs/001-tor-route/research.md §9 (AUTH_REQUIRED sub-negotiation reference, not literal scope here)
reviews: { round: 1, date: 2026-07-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T019: Author the privacy-safe error template literal

## Context

Derived from `specs/001-tor-route/tasks.md` (T019). The data plane emits a
fixed privacy-safe HTML body on HTTP CONNECT error responses per arch §10.2
and `specs/001-tor-route/contracts/error-template.md §"Response body"`.
This ticket authors the **template literal** — the exact byte sequence
stored as a single Go string constant — in
`data-plane/internal/errortpl/template.go`. The renderer that substitutes
`{ROUTE_LABEL}`, `{CODE}`, `{LOCAL_REFERENCE_ID}` lives in T048 / T071;
T019 carries no rendering logic.

## Analysis

- **Must hold:**
  - The Go constant's bytes are byte-for-byte equal to the code-block
    content of `contracts/error-template.md §"Response body"` — no
    whitespace variation, no extra elements, no inline CSS/JS.
  - Line endings are LF (single `\n`), not CRLF. (Trueness-of-source: the
    contract file is checked in with LF; the Go raw string literal
    preserves whatever bytes are inside the backticks.)
  - The ONLY placeholder tokens in the constant are `{ROUTE_LABEL}`,
    `{CODE}`, `{LOCAL_REFERENCE_ID}` — any other `{...}` sequence is
    forbidden (would either be a typo'd substitution slot the renderer
    doesn't know about, or an unrelated literal brace).
  - The UTF-8 middle-dot `·` (U+00B7, bytes `0xC2 0xB7`) in
    `<p>Code: {CODE} · Reference: ...` is preserved byte-for-byte.
    Naive re-typing in some editors swaps it for `·` ASCII look-alikes
    (e.g. bullet `•` U+2022, or `·` U+0387); the unit test gates this.
  - No rendering logic — no `strings.ReplaceAll`, no `fmt.Sprintf`, no
    `text/template`. T019 is the literal ONLY; T048 / T071 own the
    renderer.
- **Gated:**
  - The Go compiler + `go vet` verify the constant is a valid Go raw
    string literal.
  - License-header check (`scripts/check-license-headers.sh`) gates the
    SPDX header on the new Go file.
  - The unit test (`template_test.go`, this ticket) gates the
    byte-exact-match + permitted-tokens-only + LF-only properties.
- **Residue:**
  - "Cross-file drift between `contracts/error-template.md §"Response
    body"` and this Go constant" — T019's unit test asserts the constant
    against its OWN inline expected bytes (hand-synced from the contract
    at /start), NOT against the contract file directly. A future edit
    to the contract without a corresponding edit to this constant would
    silently drift. Promotable to gated by extending the unit test to
    parse the contract file at test time (T018's
    `docker_socket_proxy_section_test.sh` extraction pattern) — deferred
    to T029 / `tests/contract/error-template/body_byte_match_test.go`
    which is the contract's designated drift catcher at the renderer
    layer. Filed as a residue item so the future ticket knows the gap
    exists today.
  - "Trailing newline after the final `</p>`" — the contract code block's
    closing ` ``` ` on a separate line is markdown syntax; whether the
    literal ends with `</p>` or `</p>\n` is ambiguous from the contract
    text alone. T019 picks "ends with `</p>`" (no trailing newline)
    because that is the visible template content. T029 / the renderer
    ticket pins this down definitively at the wire-format layer; if the
    renderer needs a trailing LF, that's a renderer concern, not a
    template-literal concern.

## Acceptance

1. New file `data-plane/internal/errortpl/template.go` declares a
   single exported Go constant — `const Template = ...` — holding the
   exact byte sequence from `contracts/error-template.md §"Response
   body"` as a Go raw string literal (backtick-delimited). Apache 2.0
   SPDX header at the top. Package `errortpl`. The file contains NO
   other code (no renderer, no helpers, no other constants).
2. The constant's bytes are exactly (LF line endings, UTF-8 middle-dot):
   ```
   <!doctype html><meta charset=utf-8>
   <title>Stargate: route unavailable</title>
   <h1>Route unavailable</h1>
   <p>The {ROUTE_LABEL} route is currently not serving requests.</p>
   <p>Code: {CODE} · Reference: {LOCAL_REFERENCE_ID}</p>
   <p>See the admin dashboard for details.</p>
   ```
   No trailing newline.
3. New file `data-plane/internal/errortpl/template_test.go` (package
   `errortpl`, Apache 2.0 SPDX header) defines `TestTemplateLiteral`
   with sub-tests asserting:
   - `ByteExactMatch`: `[]byte(Template)` equals an inline expected
     byte slice hand-copied from the contract at /start.
   - `OnlyPermittedPlaceholderTokens`: a regex scan
     (`\{[A-Z_]+\}`) over `Template` returns exactly the set
     `{ROUTE_LABEL, CODE, LOCAL_REFERENCE_ID}` — no fewer (renderer
     would have nothing to substitute), no more (forbidden tokens).
   - `LFOnlyLineEndings`: `strings.IndexByte(Template, '\r') == -1`
     (no CRLF contamination from a Windows edit).
   - `MiddleDotPreserved`: the byte sub-slice `0xc2 0xb7` (UTF-8 `·`)
     appears in `[]byte(Template)` exactly once (in the
     `Code: {CODE} · Reference:` line); any look-alike ASCII
     substitute would fail this.
   - `NoTrailingNewline`: `Template` does not end with `'\n'` (matches
     the contract code block's visible content; see §Residue trailing-
     newline item).
4. `scripts/verify.sh` is GREEN. The new test runs in gate 2
   (`go test ./...` from `data-plane/`).

## Out-of-scope

- The renderer (`render.go`) is T048 / T071. T019 authors the literal
  only; any substitution logic — even a one-line helper — is out of
  scope and would step on T048/T071's files_scope.
- `tests/contract/error-template/*` is owned by a separate ticket per
  the contract's test table. T019 does not author any contract test
  under `tests/contract/`.
- The contract document itself (`contracts/error-template.md`) is NOT
  amended by T019. If the contract drifts, the residue item in §Analysis
  captures the gap; a contract amendment is a separate concern.
- Header template / status-line / reason-phrase tables are NOT authored
  here — only the response body template. T048 wires the full wire-
  format response together.

## Notes

- Why a raw string literal (backticks) rather than a double-quoted
  string with `\n` escapes: the contract is byte-for-byte pinned, and
  raw literals make whitespace visibility unambiguous in code review.
  A double-quoted string would tempt future editors to add escape
  sequences; the backtick form is self-documenting as "this is a
  literal."
- Why no `text/template` machinery: Go's `text/template` would parse
  the `{...}` tokens as invalid syntax (Go template syntax is
  `{{...}}`). The renderer will use `strings.ReplaceAll` per T048 /
  T071; the constant just holds the bytes.
- The contract's prose says "Line endings are `\n` (single LF)" — the
  Go raw string literal preserves whatever is between the backticks,
  which on a Linux/macOS editor is LF. The unit test gates against CRLF
  contamination from a Windows edit.
- The constant is exported (`Template`, not `template`) because T048 /
  T071 will import it from outside the `errortpl` package. Lowercase
  would force them into the same package, breaking separation of
  concerns.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance derived at `/start` 2026-07-05 against HEAD `d5e9b9c`.
