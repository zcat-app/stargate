---
id: 20260706-001-leakscan-encoding-gaps
status: fixed
severity: major
principle: [III, VII]
threat-model: n/a
location: tests/contract/control-grpc/dpharness_test.go:378
first-seen-run: 20260706-b906efb
first-seen-date: 2026-07-06
fix-commit: same-run — fixed pre-merge, lands in T020's ticket commit (findSecretLeaks + leakscan_test.go negative controls)
decision-ref: null
---

# Leak scan misses realistic logger encodings — no-log contract under-pinned

## What the code does

`assertNoSecretLeak` (`tests/contract/control-grpc/dpharness_test.go:378-397`)
scans the captured DP journal for each secret in exactly four encodings:

```go
encodings := map[string]string{
    "hex":        hex.EncodeToString(secret),
    "HEX":        strings.ToUpper(hex.EncodeToString(secret)),
    "base64":     base64.StdEncoding.EncodeToString(secret),
    "base64-raw": base64.RawStdEncoding.EncodeToString(secret),
}
```

It does not check base64 URL/RawURL encoding, nor the decimal byte-slice
form `[12 34 56 …]` that Go's `slog` TextHandler and any
`fmt.Printf("%v"/"%+v", b)` emit for a `[]byte`. Every `ReloadTokens`
sub-test relies on this helper as the enforcement of the contract's
final bullet.

## Why it leaks

The contract (`specs/001-tor-route/contracts/control-grpc.md`
§"ReloadTokens · Contract", final bullet; `data-model.md` §1.6) states the
data plane MUST NOT log the hash bytes, the salt bytes, or any token
label. This is a Principle III privacy property, and per Principle VII
this contract test *is* the regression line that keeps it true across
future DP changes. The adversary is anyone with read access to the DP
journal / container logs (operator, log-shipping pipeline, a co-located
process). The argon2id hash + its salt are exactly what an offline
brute-forcer of a leaked bearer token needs (data-model.md §1.5 sizes the
argon2 cost precisely for this threat). A T045/T050 implementer who logged
a token via idiomatic structured logging —
`slog.Info("reload", "gen", g, "hash", th.Hash)` on a text handler, or a
stray `log.Printf("token %v", th.Hash)` — would emit the hash to the
journal in decimal-slice form, which the current scan does not match. The
test goes green; the leak ships. base64url is the same story for any
logger that URL-encodes byte fields.

## Suggested fix

Extend the `encodings` map in `assertNoSecretLeak` with the missing forms,
keeping the existing four:

- `base64.URLEncoding.EncodeToString(secret)`
- `base64.RawURLEncoding.EncodeToString(secret)`
- decimal slice: `fmt.Sprintf("%v", secret)` (yields `[12 34 …]`) — this
  covers `slog` TextHandler and `%v`/`%+v` format-string logging, the most
  common accidental path.

Optionally also a space-joined `%d` run without brackets. Leave the hex and
base64-std/raw-std entries in place. This is a pure test-file change under
`tests/contract/`; it does not touch runtime source and cannot itself leak
(the map values are compared, never logged; failure messages already print
only the secret index at `dpharness_test.go:393`).

## Regression test

The fix *is* a strengthening of a contract assertion, so the regression is
self-demonstrating: add a negative-control sub-test (or a table row in a
small unit test alongside the harness) that feeds `assertNoSecretLeak` a
synthetic journal string containing a known secret rendered in each new
encoding (`slog`-style decimal slice, base64url) and asserts the scan now
reports a leak (e.g. by running it against a `*testing.T` stub and checking
`Failed()`). This proves the scan would have caught a DP that logs the hash
via `slog`/`%v` — the exact failure mode the current four-encoding map lets
through. Lives in `tests/contract/control-grpc/` (e.g.
`leakscan_test.go`), needs no DP process, so it runs even while the
content gate skips `TestReloadTokens`.

## Related

- Companion Minor M2 in the same run (plaintext-token scan inconsistent
  across sub-tests) touches the same helper's call sites.
- T025 (`socks5/leak-invariants`) owns the SOCKS5 auth-path no-leak surface
  in full; this helper is the `ReloadTokens`-path counterpart and should
  share the same encoding corpus once T025 lands to avoid drift.
