---
id: "20260929-005-revocation-status-invisible"
status: "open"
severity: "major"
principle: ["II", "III"]
threat-model: "5.15"
location: "control-plane/core/src/main/java/app/zcat/stargate/auth/TokenLoader.java:326"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: null
decision-ref: null
remediation-ticket: "T187"
---

# Pending or stale revocation is invisible and counted before acknowledgement

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A2-M3**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T187** under `specs/001-tor-route/tickets/`.
Use its acceptance probes and the canonical review flow. This open record is
not a risk acceptance.
