---
id: T012a
title: 'Unit test for the bind-safety check in `data-plane/internal/bind/check'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T012a
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # corrected by hand: T012a is the test-first red for T013 (Constitution VII); does not depend on T013
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: ['spec.md#FR-010', 'constitution.md#VII', 'architecture/spec.md#10.1']   # filled at /start
decision_refs: []
reviews: { round: 1, date: 2026-07-04, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T012a: Unit test for the bind-safety check in `data-plane/internal/bind/check

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for the bind-safety check in `data-plane/internal/bind/check_test.go` (precedes T013; Principle VII — bind/routing decisions are privacy-critical, FR-010 prevents the local-profile loopback-only invariant from drifting). Table-driven cases assert: (a) IPv4 loopback `127.0.0.1` and other `127.0.0.0/8` addresses accepted; (b) IPv6 loopback `::1` accepted; (c) `0.0.0.0`, `::`, RFC1918 (`192.168.x.x`, `10.x.x.x`, `172.16.x.x`), link-local (`169.254.x.x`, `fe80::/10`), and any public-routable IP rejected with the package's `BIND_REFUSED` error sentinel; (d) DNS names (`localhost`, arbitrary strings) rejected — the check operates on parsed IP literals only, so name resolution cannot smuggle a non-loopback bind past it; (e) malformed inputs (empty string, garbage bytes) rejected. Pure unit test — no listener side effects, no goroutines, no sockets. Pairs with T013 (impl) and is referenced from T050's startup sequence (`bind/check.go` runs FIRST before any listener opens).

## Analysis

**Contract this test pins** (the API T013 must implement):

```go
package bind

import "errors"

var ErrBindRefused = errors.New("BIND_REFUSED")

// Check verifies addr is a loopback IP literal (FR-010). Returns nil if
// addr parses as a loopback IP; returns ErrBindRefused for any non-loopback
// IP, DNS name, malformed input, or empty string. Pure function — no socket
// or listener side effects.
func Check(addr string) error
```

**Must hold** (Constitution Principle VII — bind/routing is privacy-critical; FR-010):

1. Every IP in `127.0.0.0/8` is accepted (loopback is the whole /8, not just `127.0.0.1`).
2. IPv6 loopback `::1` is accepted.
3. `0.0.0.0`, `::`, RFC1918 (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`, `fe80::/10`), and any public-routable IP are rejected with `errors.Is(err, ErrBindRefused) == true`.
4. DNS names (`localhost`, arbitrary hostnames) are rejected — the function operates on **parsed IP literals only**, so name resolution cannot smuggle a non-loopback bind past it. This is the load-bearing property: a future "helpful" refactor that resolves hostnames before checking would silently break the local-profile invariant.
5. Malformed inputs (empty string, garbage bytes) are rejected with the same sentinel.
6. The function is pure: no goroutines, no sockets, no listener side effects, no DNS lookups.

**Gated** (verify.sh catches fail-closed):

- Go gate (`go vet` + `go test ./...`) catches a regression in any of (1)–(5) **on a host that has the Go toolchain installed**. This host does NOT — verify.sh reports the go gate as SKIP. CI/dev environments with `go` installed will run the test.
- License header → `check-license-headers.sh`.

**Residue** (no gate catches):

- **Purity (item 6)** — no static check enforces "no `net.Listen` / `net.ResolveTCPAddr` / `net.LookupHost` inside the function." A future implementation that opens a socket or resolves DNS would pass the table-driven test (which only inspects the return value) while violating the no-side-effects contract. Addressed in T013's impl + the T050 startup sequence (which calls `bind.Check` before any listener opens, so a side-effecting impl would surface as a double-listen in integration). Flagged for `stargate-redteam` at T013.
- **Compile-red test-first state** — until T013 lands `check.go`, the test does not compile (undefined `bind.Check`, `bind.ErrBindRefused`). That is the intended test-first red state per Principle VII; verify.sh's go gate being SKIP on this host means the red state is only observable on a go-equipped host. T013 landing the impl turns the test green.

## Acceptance

**Named test** (`data-plane/internal/bind/check_test.go`):

`TestCheck` — single table-driven test covering every task-body case (a)–(e). Each row asserts either `err == nil` (accept case) or `errors.Is(err, ErrBindRefused)` (reject case). Specifically:

- **(a) IPv4 loopback /8 accepted:** `127.0.0.1`, `127.0.0.0`, `127.0.0.2`, `127.255.255.255`.
- **(b) IPv6 loopback accepted:** `::1`.
- **(c) Non-loopback rejected with `ErrBindRefused`:** `0.0.0.0`, `::` (IPv6 wildcard), `192.168.1.1`, `10.0.0.1`, `172.16.0.1`, `172.31.255.255` (edge of 172.16/12), `169.254.1.1` (IPv4 link-local), `fe80::1` (IPv6 link-local), `8.8.8.8` (public-routable).
- **(d) DNS names / arbitrary strings rejected:** `localhost`, `example.com`, `not-an-ip`.
- **(e) Malformed / empty rejected:** `""` (empty), `"   "` (whitespace), `"[::1]"` (bracketed — IP-literal URI form, not bare literal).

**Test-first red state (Principle VII):** until T013 lands, the test does not compile (`undefined: bind.Check`). T013's green criterion is `cd data-plane && go test ./internal/bind/...` returning 0 with all rows passing.

**Runnable command:** `bash scripts/verify.sh` — go gate is SKIP on hosts without the toolchain, but the test compiles+passes on any host with `go >= 1.26` installed (CI / dev workstation).

## Out-of-scope

- The `Check` implementation itself — that is T013. This ticket ships the test that pins the contract T013 must satisfy.
- Integration of `bind.Check` into the data-plane startup sequence — that is T050 (the startup sequence calls `bind.Check` before any listener opens).
- A purity static-check (e.g., a `staticcheck` or `ruleguard` rule forbidding `net.Listen` in the `bind` package). Residue acknowledged above; deferred until a future hardening ticket or `stargate-redteam` recommendation.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
