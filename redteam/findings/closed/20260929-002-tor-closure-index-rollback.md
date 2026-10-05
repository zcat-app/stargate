---
id: "20260929-002-tor-closure-index-rollback"
status: "closed"
severity: "major"
principle: ["IV", "VI"]
threat-model: "2.3"
location: "sidecars/tor/Dockerfile:150"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: "a7af44d"
decision-ref: 'SECURITY-DECISIONS.md "2026-09-30 — Refuse rolled-back Debian snapshot metadata for the Tor image (T184)"'
remediation-ticket: "T184"
closed-date: "2026-10-05"
closed-by: "T184 pins the snapshot InRelease hash and per-arch package closure in package-closure.lock, checked by verify-closure.sh after every apt update in both stages; a replayed 12.12 index and a tampered lock row are refused"
---

# Tor sidecar package closure accepts an older signed index (libssl3 rollback)

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A3-M1**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Closed by T184 (a7af44d; the maintainer approved the SD entry in
2568da0). `tests/reproducibility/tor_sidecar_manifest_test.sh` carries the rollback-proxy and
tampered-lock negative controls, recorded red/green in
`specs/001-tor-route/evidence/T184-tests-first.json`.
