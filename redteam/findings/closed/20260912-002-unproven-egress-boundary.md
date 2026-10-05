---
id: "20260912-002-unproven-egress-boundary"
status: "closed"
severity: "major"
principle: ["III", "V"]
threat-model: "3.1 / 5.8"
location: "compose/docker-compose.local.yml:290"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: "1cf881d; ba3df24; 7b56db5"
decision-ref: 'SECURITY-DECISIONS.md "2026-09-21 — Retire T125 embedded-resolver acceptance on the measured Local boundary (T163)"'
remediation-ticket: "T134"
closed-date: "2026-10-05"
closed-by: "T162/T168 deny DP-UID egress with owner rules, Landlock and seccomp on a host-netns DP; T163 and T155's 2026-10-05 F1 run captured IPv4/IPv6 TCP/UDP/DNS denial with unrestricted-UID positive controls"
---

# No-masquerade and failed TCP probes do not establish egress denial

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M1**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner **T134**, implemented by T162 (1cf881d) and T168
(ba3df24), and verified at packet level by T163 (7b56db5). T155's (c688164) 2026-10-05 F1 run repeated
the egress matrix on the candidate, with positive controls, owner-rule loss and re-init, and
confinement-unavailable refusals (`evidence/T155-live-results.json`). Residue:
- physical-NIC egress capture → T034f (README R-2);
- routed IPv6, LAN/VPS → README R-7 (owned by T078);
- running-DP AppArmor label check → T209.
