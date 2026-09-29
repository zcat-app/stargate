---
id: "20260929-004-blocked-null-is-direct"
status: "open"
severity: "major"
principle: ["III"]
threat-model: "4.2"
location: "extension/background/router.js:381"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: null
decision-ref: null
remediation-ticket: "T186"
---

# Blocked protected proxy result is Firefox explicit DIRECT

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A2-M1**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T186** under `specs/001-tor-route/tickets/`.
Use its acceptance probes and the canonical review flow. This open record is
not a risk acceptance.
