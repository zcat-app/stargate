---
id: "20260912-005-aged-reload-deadline"
status: "open"
severity: "major"
principle: ["II", "III"]
threat-model: "5.14"
location: "control-plane/api/src/main/java/io/quarkus/stargate/control/grpc/ReloadTokensClient.java:60"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: null
decision-ref: null
remediation-ticket: "T137"
---

# ReloadTokens deadline expires before the first call

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M4**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner: **T137** under `specs/001-tor-route/tickets/`.
Use its named acceptance probes and canonical review flow; do not amend the
original approved commit. This open record is not a risk acceptance.
