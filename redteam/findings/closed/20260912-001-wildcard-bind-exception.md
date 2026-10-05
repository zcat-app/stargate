---
id: "20260912-001-wildcard-bind-exception"
status: "closed"
severity: "blocker"
principle: ["III"]
threat-model: "3.1"
location: "data-plane/internal/bind/check.go:91"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: "1cf881d"
decision-ref: 'SECURITY-DECISIONS.md "2026-09-20 — Withdraw T125 wildcard/no-masquerade local posture (T162)"'
remediation-ticket: "T134"
closed-date: "2026-10-05"
closed-by: "T162 removed the container-flag exception (CheckListener is exception-free) and moved the DP to a host-netns strict 127.0.0.1:8881 listener; T155's 2026-10-05 clean-volume F1 run found non-loopback and ::1 closed"
---

# Wildcard environment exception defeats the bind invariant

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **B1**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner **T134**, implemented by T162 (1cf881d).
`data-plane/internal/bind/check_test.go` refuses wildcard and non-loopback literals. T155's
2026-10-05 F1 (`tests/live-e2e/local-topology/run.py`, exit 0, 52 pass) bound the candidate in
`specs/001-tor-route/evidence/T155-live-results.json`. Residue: those are guest-kernel claims
only. Routed IPv6, LAN/VPS, physical NIC and hypervisor behaviour stay release-cadence item R-7
in `specs/001-tor-route/live-e2e/README.md`, owned by T078, never recorded as PASS.
