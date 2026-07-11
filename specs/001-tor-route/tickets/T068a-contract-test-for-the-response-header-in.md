---
id: T068a
title: 'Contract test for the **response-header invariants** of the privacy-sa'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T068a
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: [T009]   # T096/M6: removed inverted T048 dep — the test must NOT wait on its impl (Constitution VII)
parallel: true
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

# T068a: Contract test for the **response-header invariants** of the privacy-sa

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for the **response-header invariants** of the privacy-safe template — `tests/contract/error-template/header_set_test.go`. Gates FR-009 + spec US3 acceptance-scenario 2 ("they contain exactly `Content-Type`, `Content-Length`, `Cache-Control: no-store`, and `X-Stargate-Error: <CODE>` — and no other headers") + error-template.md §"Response headers" ("Exactly these four headers, in this order, no others"). For one CONNECT-path failure of each of the four codes (`AUTH_REQUIRED`, `ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT`) — using the per-code setups from T065–T067 + T027 — capture the response header block (every byte from the status line up to and including the blank line that terminates headers). Assert: (a) **header count is exactly four**; (b) **order matches the contract** — `Content-Type`, `Content-Length`, `Cache-Control`, `X-Stargate-Error` (case-sensitive, as serialised on the wire); (c) `Content-Type: text/html; charset=utf-8` byte-for-byte; (d) `Content-Length` parses to a non-negative integer that matches the actual body length emitted in the same response; (e) `Cache-Control: no-store` byte-for-byte; (f) `X-Stargate-Error: <CODE>` where `<CODE>` matches the failure code under test; (g) **no occurrence of any forbidden header name** in the captured block — the closed set asserted absent is `{Server, Via, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-Port, Proxy-Agent, Date, Connection, Keep-Alive, Transfer-Encoding}` (the spec's enumerated forbidden list plus the headers Go's `net/http` server adds by default if not suppressed, so a regression to `http.Server` defaults trips this test); (h) leak-corpus scan over every captured header byte (corpus per error-template.md §"Leak-corpus invariant") returns zero hits. Pairs with T048/T071 (the renderer is what enforces the header set on the wire). T068a MUST be authored and failing before T048 lands (Principle VII — header handling is a privacy-critical category per the constitution discipline table).

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
