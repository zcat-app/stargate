---
id: "20260929-003-maven-deps-unlocked"
status: "open"
severity: "major"
principle: ["IV", "VI"]
threat-model: "5.9"
location: "control-plane/Dockerfile:78"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: null
decision-ref: null
remediation-ticket: "T185"
---

# Control-plane Maven dependencies have no locked content identity

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A3-M2**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T185** under `specs/001-tor-route/tickets/`.
Use its acceptance probes and the canonical review flow. This open record is
not a risk acceptance.
