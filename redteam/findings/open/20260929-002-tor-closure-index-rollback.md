---
id: "20260929-002-tor-closure-index-rollback"
status: "open"
severity: "major"
principle: ["IV", "VI"]
threat-model: "2.3"
location: "sidecars/tor/Dockerfile:150"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: null
decision-ref: null
remediation-ticket: "T184"
---

# Tor sidecar package closure accepts an older signed index (libssl3 rollback)

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A3-M1**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T184** under `specs/001-tor-route/tickets/`.
Use its acceptance probes and the canonical review flow. This open record is
not a risk acceptance.
