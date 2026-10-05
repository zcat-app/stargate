---
id: "20260912-006-clean-start-evidence-gap"
status: "closed"
severity: "major"
principle: ["II", "VII"]
threat-model: "3.1"
location: "compose/docker-compose.local.yml:166"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: "e33dc3b"
decision-ref: null
remediation-ticket: "T123"
closed-date: "2026-10-05"
closed-by: "T167's installer provisions the keys child of the read-only config volume (T123 validated it); T155's 2026-10-05 F1/F2 runs reached authenticated Tor-routed bytes from fresh volumes through real scripts/stargate init with no harness provisioning"
---

# Clean CP startup lacks mount setup supplied by the test harness

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M6/M7**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner **T123**, which validated the repair T167
delivered (e33dc3b). T124 (44ffc25) supplied the cold-bootstrap window, and T191 item 8 removed
the smoke-test compensations. `tests/contract/compose/control_mount_test.sh` and
`init_docker_test.sh` are the regressions. T155's (c688164) 2026-10-05 F1 and F2 are the live clean-volume
evidence (`evidence/T155-live-results.json`). Residue: a clean physical reference host → T077.
