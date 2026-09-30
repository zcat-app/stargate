---
id: "20260929-005-revocation-status-invisible"
status: "closed"
severity: "major"
principle: ["II", "III"]
threat-model: "5.15"
location: "control-plane/core/src/main/java/app/zcat/stargate/auth/TokenLoader.java:326"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: "b6dde00"
decision-ref: null
remediation-ticket: "T187"
closed-date: "2026-09-30"
closed-by: "T187 counts enrolled/revoked only after the DP acknowledges the exact generation (never at commit or on a stale refusal) and adds `scripts/stargate status`, which reads the running CP's current delivery state (PENDING, ACKNOWLEDGED(<generation>), STALE_CONFLICT; UNKNOWN when none is published) from a CP-private volatile tmpfs file with no history, timestamps or labels; red before green in core and runtime tests, and a live run on the real DP + CP images covered pending, acknowledged, stale conflict and its documented recovery"
---

# Pending or stale revocation is invisible and counted before acknowledgement

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A2-M3**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T187** under `specs/001-tor-route/tickets/`.
Closed by T187 (b6dde00): `TokenLoader` defers the diff counts to the exact
DP acknowledgement, `GrpcReloadChannel` owns and publishes the current
delivery state, and `scripts/stargate status` reports it with distinct exit
codes. The regressions are the T187 tests in `TokenLoaderTest` and
`StargateControlPlaneTest`; the evidence is
`specs/001-tor-route/evidence/T187-tests-first.json`. The stale-conflict
recovery procedure is in the quickstart, and the residues (CP-process scope,
restart undercount, advisory status) are in THREAT-MODEL §5.15.
