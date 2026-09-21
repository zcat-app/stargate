---
id: T070a
title: 'Integration test for mid-request Tor circuit drop (Principle I no-retr'
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T070a
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156"]
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

# T070a: Integration test for mid-request Tor circuit drop (Principle I no-retr

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Integration test for mid-request Tor circuit drop (Principle I no-retry + Principle III no-upstream-derived-leak; spec §"Edge Cases" — *Tor circuit failure mid-request*) — bring up the local-profile stack; using the cookie-authenticated control-port helper from T062, open an authenticated CONNECT through port 8881 to a known-reachable `.onion`, begin a slow read so the stream stays in-flight, then issue `CLOSECIRCUIT <id>` on the control port to kill *that specific circuit* (not the whole sidecar); capture every byte written to the browser side until the browser-side socket finishes closing; assert (a) after the data plane observes EOF (or RST) on the upstream SOCKS5 stream, zero new bytes are written to the browser side — the data plane MUST NOT synthesise an error template, status line, or reason text at this layer (in-flight bytes Tor delivered before the close are passed through verbatim and are tested only against the leak-corpus scan in assertion (d)); (b) the browser-side socket is closed by the data plane (TCP close, not a rendered HTTP response — the post-CONNECT byte pipe has no framing context for one); (c) the data plane issues no retry to the Tor sidecar (verified by control-port `circuit-status` showing no new circuit for the same SOCKS5 username within a bounded watch window); (d) leak-corpus scan over the captured bytes returns zero matches; (e) the T025a shared log allowlist applies to the data plane's output during the run — in `tests/integration/circuit_drop_midstream_test.go`. Run before each release tag, not on every PR (real-Tor reachability + control-port timing make this unsuitable as a per-PR gate; same cadence as T034a).

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

## T172 selected acceptance (supersedes conflicting historical task text)

Open an authenticated SOCKS5 CONNECT with the complete partition username; after killing its identified Tor circuit, assert no injected bytes after upstream EOF/RST, browser-side close, no retry/new circuit for that username, no corpus/log hit. Preserve early/in-flight byte transparency. The historical `CONNECT` references below mean the SOCKS command.
