---
id: "20260912-003-resumed-peer-pin-bypass"
status: "open"
severity: "major"
principle: ["II", "III"]
threat-model: "5.13"
location: "data-plane/internal/controlclient/tls.go:205"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: null
decision-ref: null
remediation-ticket: "T135"
---

# Resumed TLS peer bypasses replacement of cp.pub

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M2**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner: **T135** under `specs/001-tor-route/tickets/`.
Use its named acceptance probes and canonical review flow; do not amend the
original approved commit. This open record is not a risk acceptance.
