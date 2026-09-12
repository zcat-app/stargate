---
id: "20260912-004-firstparty-suffix-collisions"
status: "open"
severity: "major"
principle: ["III"]
threat-model: "5.10"
location: "extension/lib/firstparty.js:109"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: null
decision-ref: null
remediation-ticket: "T136"
---

# Distinct registrable first parties share the Tor isolation key

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M3**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner: **T136** under `specs/001-tor-route/tickets/`.
Use its named acceptance probes and canonical review flow; do not amend the
original approved commit. This open record is not a risk acceptance.
