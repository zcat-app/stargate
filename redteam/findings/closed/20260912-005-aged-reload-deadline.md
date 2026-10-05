---
id: "20260912-005-aged-reload-deadline"
status: "closed"
severity: "major"
principle: ["II", "III"]
threat-model: "5.14"
location: "control-plane/api/src/main/java/io/quarkus/stargate/control/grpc/ReloadTokensClient.java:60"
first-seen-run: "20260912-677960b"
first-seen-date: "2026-09-12"
fix-commit: "f9f7058"
decision-ref: null
remediation-ticket: "T137"
closed-date: "2026-10-05"
closed-by: "T137 gives every ReloadTokens attempt a fresh withDeadlineAfter; an aged client against a reachable authenticated peer gets the full deadline"
---

# ReloadTokens deadline expires before the first call

## Evidence, attempted falsification and limits

See the immutable [foundation audit](../../../reviews/redteam-20260912-677960b.md),
section **M4**, and its linked preserved probes. That section records
the reachable path, actual versus required behavior, attempted falsification,
and exactly which live behavior was or was not demonstrated.

## Remediation and regression

Closed by T137 (f9f7058). `InterPlaneWireTest`
(`reloadClientGetsFullDeadlineAfterIdlingPastConstructionDeadline`) and
`StargateControlPlaneTest` are the regressions. T155's (c688164) 2026-10-05 F2 acknowledged an idle reload
after 180 s.
