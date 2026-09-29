---
id: "20260929-001-dns-leak-gate-stale"
status: "open"
severity: "major"
principle: ["III", "VII"]
threat-model: "n/a"
location: "tests/integration/dns_leak_test.go:240"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: null
decision-ref: null
remediation-ticket: "T183"
---

# The T034 DNS-leak gate cannot run against the current DP

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A1-M2**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T183** under `specs/001-tor-route/tickets/`.
Use its acceptance probes and the canonical review flow. This open record is
not a risk acceptance.
