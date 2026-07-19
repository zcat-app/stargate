---
id: T044
title: 'Implement `data-plane/internal/auth/token.go`'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T044
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T092, T093]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T044: Implement `data-plane/internal/auth/token.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/auth/token.go` — argon2id-hash candidate token using shared `Argon2idParams` (T011) and the per-token salt from the current generation; compare with `crypto/subtle.ConstantTimeCompare`; never log the offered token or hash. Verified by T024, T025, T027, T028.

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**T092 amendment (2026-07-15) — consume the amended contract.**
`auth/token.go` must: (a) compute the candidate's verifier ONCE per request
as `HMAC-SHA-256(pepper, candidate)` reading the pepper from
`/etc/stargate/keys/pepper.key` (`data-model.md` §1.5), NOT Argon2id; (b)
compare with `crypto/subtle.ConstantTimeCompare` against EVERY verifier in
the current generation with NO short-circuit on first match (timing must
be independent of which slot matched); (c) keep per-request allocation
O(1) — this is the sol-review B5 fix; the falsifier is T079a's peak-RSS +
unauthenticated-flood bounds, not a pool-fill timing test. The retired
N ≤ 4 cap and the `argon2` import are gone. **This ticket also owns the
shared constants rewrite** that T011 (done) shipped against the now-retired
contract: replace `data-plane/internal/auth/params.go`'s `Argon2idParams`
with `auth.PepperLen` (`32`) and `auth.VerifierAlgo` (`HMAC-SHA-256`),
drop the `golang.org/x/crypto/argon2` import, and update the file's
header comment to reference `data-model.md` §1.5 (the Go-side mirror of
the CP-side constants lands in T035's `TokenLoader` path). T093
(blocked_by T092) gates this ticket test-first.
