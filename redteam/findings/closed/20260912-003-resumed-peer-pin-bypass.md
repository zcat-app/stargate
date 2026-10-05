---
id: "20260912-003-resumed-peer-pin-bypass"
status: "closed"
severity: "major"
principle: ["II", "III"]
threat-model: "5.13"
location: "data-plane/internal/controlclient/tls.go:205"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: "c8320ca"
decision-ref: null
remediation-ticket: "T135"
closed-date: "2026-10-05"
closed-by: "T135 pins the peer in VerifyConnection, which runs on full and resumed handshakes; the resumed-peer rotation regression and T155's live wireprobe resume phase refuse the old identity"
---

# Resumed TLS peer bypasses replacement of cp.pub

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M2**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Closed by T135 (c8320ca).
`data-plane/internal/controlclient/controlclient_test.go`
(`TestGRPCServerReauthorizesResumedPeerAfterPinRotation`) and `tls_lifecycle_test.go` are the
regressions. In T155's (c688164) 2026-10-05 F2 run, a resumed old ticket after rotation took the
pin-verified PSK path and got no RPC, while the rotated identity was answered. That run does
not claim a completed Finished or the rejection cause.
