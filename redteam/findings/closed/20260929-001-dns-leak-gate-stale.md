---
id: "20260929-001-dns-leak-gate-stale"
status: "closed"
severity: "major"
principle: ["III", "VII"]
threat-model: "n/a"
location: "tests/integration/dns_leak_test.go:240"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: "67d6167"
decision-ref: null
remediation-ticket: "T183"
closed-date: "2026-09-29"
closed-by: "T183 rebuilt the gate on the production DP boot path; red (mutated DP resolving targets) fails with captured DNS, green passes with pre/post positive controls on lo + egress, in a digest-pinned public image"
---

# The T034 DNS-leak gate cannot run against the current DP

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A1-M2**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T183** under `specs/001-tor-route/tickets/`.
Closed by T183 (67d6167): `tests/integration/dns_leak_test.go` boots the real
DP through its production interface and is recorded red/green in
`specs/001-tor-route/evidence/T183-tests-first.json`; `verify.sh` names the
test with its skip reason when capture is unavailable.
