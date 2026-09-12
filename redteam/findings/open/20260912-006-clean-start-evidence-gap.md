---
id: "20260912-006-clean-start-evidence-gap"
status: "open"
severity: "major"
principle: ["II", "VII"]
threat-model: "3.1"
location: "compose/docker-compose.local.yml:166"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: null
decision-ref: null
remediation-ticket: "T123"
---

# Clean CP startup lacks mount setup supplied by the test harness

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M6/M7**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner: **T123** under `specs/001-tor-route/tickets/`.
Use its named acceptance probes and canonical review flow; do not amend the
original approved commit. This open record is not a risk acceptance.
