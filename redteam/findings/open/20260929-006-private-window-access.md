---
id: "20260929-006-private-window-access"
status: "open"
severity: "major"
principle: ["III"]
threat-model: "4.2"
location: "extension/background/router.js:372"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: null
decision-ref: null
remediation-ticket: "T188"
---

# Extension without private-window access silently yields to the ordinary proxy

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A2-m4**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T188** under `specs/001-tor-route/tickets/`.
Use its acceptance probes and the canonical review flow. This open record is
not a risk acceptance.
