---
id: "20260912-001-wildcard-bind-exception"
status: "open"
severity: "blocker"
principle: ["III"]
threat-model: "3.1"
location: "data-plane/internal/bind/check.go:91"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: null
decision-ref: null
remediation-ticket: "T134"
---

# Wildcard environment exception defeats the bind invariant

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **B1**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner: **T134** under `specs/001-tor-route/tickets/`.
Use its named acceptance probes and canonical review flow; do not amend the
original approved commit. This open record is not a risk acceptance.
