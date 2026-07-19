---
id: T013
title: 'Implement `data-plane/internal/bind/check.go`'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T013
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006, T012a]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T013: Implement `data-plane/internal/bind/check.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/bind/check.go` — the loopback-only bind-safety check (FR-010) that runs before any listener opens; returns `BIND_REFUSED` and exits non-zero on violation. Pure unit-tested function (no listener side effects). Test gate: T012a MUST be authored and failing before this task lands.

## Analysis

**Contract inherited from T012a** (the test-first red state T013 turns
green):

```go
package bind

var ErrBindRefused = errors.New("BIND_REFUSED")
func Check(addr string) error  // nil if loopback IP literal; ErrBindRefused otherwise
```

**Must hold** (Constitution Principle VII — bind/routing is privacy-critical; FR-010):

1. Every row in `data-plane/internal/bind/check_test.go` (the T012a
   artifact) passes: `127.0.0.0/8` and `::1` accepted; everything else
   rejected with `errors.Is(err, ErrBindRefused) == true`.
2. **Purity.** The function performs no I/O of any kind: no socket, no
   listener, no goroutine, no `net.LookupHost` / `net.ResolveTCPAddr`.
   It operates on a parsed `netip.Addr` only — the load-bearing property
   that prevents name resolution smuggling a non-loopback bind past the
   FR-010 gate (the `localhost` row in T012a exists precisely to catch a
   future "helpful" resolve-then-check refactor).
3. **Sentinel preserved through wrapping.** The returned error carries
   `ErrBindRefused` via `%w` so `errors.Is` matches. The wrapper adds
   context (the offending address) for debuggability without breaking the
   sentinel match — critical because the startup sequence classifies the
   failure mode by `errors.Is`.
4. The function is the **sole** resident of `data-plane/internal/bind`
   beside its test; no listener code, no `net.Listen` call site. T050
   calls `bind.Check` before any listener opens.

**Gated** (verify.sh catches fail-closed):

- Go gate (`go vet` + `go test ./...`) catches a regression against any
  T012a row **on a go-equipped host**. This host does NOT have the go
  toolchain — verify.sh reports the go gate as SKIP. CI/dev with
  `go >= 1.26` runs the test. **Local compilation was not possible
  before this commit; the green criterion is deferred to CI.**
- License header → `check-license-headers.sh`.
- `staticcheck` / `gosec` (if installed at CI) catch a class of purity
  violations; not assumed present.

**Residue** (no gate catches; this is the @T013 redteam hook T012a routed to):

- **Purity (item 2) is not statically enforced.** A future implementation
  that opens a socket or resolves DNS inside `Check` would still pass the
  T012a table (which inspects only the return value). `stargate-redteam`
  at this ticket is the standing review for that property; the T050
  startup-ordering (calling `Check` before any listener opens) is the
  defence-in-depth that surfaces a side-effecting impl as a double-listen
  in integration.

## Acceptance

**Named test** (already authored in T012a, the test-first red state):
`data-plane/internal/bind/check_test.go::TestCheck` — 19 rows. T013's
green criterion is `cd data-plane && go test ./internal/bind/...` returns
0 with all 19 rows passing.

**Runnable command:** `bash scripts/verify.sh` — go gate SKIP on this
host (no toolchain); green on any host with `go >= 1.26` installed
(CI / dev workstation).

**Spec-fidelity floor:** the implementation uses only stdlib
(`net/netip`, `errors`, `fmt`); no third-party deps added to
`data-plane/go.mod`. `netip.ParseAddr` is the parser — pure, no network.

## Out-of-scope

- Integration of `bind.Check` into the data-plane startup sequence — T050
  (calls `bind.Check` before any listener opens; exits non-zero on
  `ErrBindRefused`).
- The `::ffff:127.0.0.1` (IPv4-mapped IPv6) test row the T012a redteam
  flagged as Info-level optional coverage. `netip` canonicalises
  IPv4-mapped addresses so `IsLoopback()` returns true for it
  (privacy-safe); adding the row would expand T012a's scope into T013.
  Deferred.
- A static-analysis rule forbidding `net.Listen` / `net.LookupHost` in
  the `bind` package. Residue; deferred to a future hardening ticket or
  a `stargate-redteam` recommendation.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
