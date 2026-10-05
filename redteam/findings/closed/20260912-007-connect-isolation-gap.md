---
id: "20260912-007-connect-isolation-gap"
status: "closed"
severity: "major"
principle: ["III"]
threat-model: "5.10"
location: "data-plane/internal/forward/tor.go:252"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: "56a4946"
decision-ref: null
remediation-ticket: "T147"
closed-date: "2026-10-05"
closed-by: "T147's contract decision and T172/T173 refuse every non-SOCKS5 ingress, HTTP CONNECT included, before auth, counters or upstream dial; T155's deployed connect_refusal.py passed"
---

# HTTP CONNECT supplies no first-party isolation identity

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **HTTP CONNECT supported-surface gap**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Executable owner **T147**, implemented by T172 (ce6aa19) and T173
(56a4946). `data-plane/internal/listener/socks5.go` silently closes non-SOCKS5 ingress, and
`connect.go` is gone. `connect_test.go` (`TestHTTPRefusalDoesNotConsultVerifier`) is the
regression, and T155's (c688164) 2026-10-05 F3 run is the deployed check.
