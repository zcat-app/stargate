---
id: "20260929-003-maven-deps-unlocked"
status: "closed"
severity: "major"
principle: ["IV", "VI"]
threat-model: "5.9"
location: "control-plane/Dockerfile:78"
first-seen-run: "20260929-694dbd8"
first-seen-date: "2026-09-29"
fix-commit: "ac57d84"
decision-ref: null
remediation-ticket: "T185"
closed-date: "2026-10-01"
closed-by: "T185 commits a 1220-entry SHA-256 lock (control-plane/.mvn/checksums/checksums.sha256) enforced by Maven Resolver trusted checksums (failIfMissing) plus --strict-checksums through control-plane/.mvn/maven.config in both the Docker build and scripts/verify.sh; tampered cached POMs, plugins and processors and unlisted artifacts fail before compilation, with red before green; amd64 closure build-confirmed, arm64 entries emulation-derived and pinned by the regression"
---

# Control-plane Maven dependencies have no locked content identity

## Evidence, attempted falsification and limits

See the [cumulative redteam report](../../../reviews/redteam-20260929-694dbd8.md),
finding **A3-M2**, for the reviewer's evidence, the falsification pass's
corrected claim and what was run versus read.

## Remediation and regression

Executable owner: **T185** under `specs/001-tor-route/tickets/`.
Closed by T185 (ac57d84): `control-plane/.mvn/maven.config` enables
`--strict-checksums` and the Resolver trusted-checksums check against the
committed `control-plane/.mvn/checksums/checksums.sha256`. The Dockerfile copies
`.mvn/` before `RUN mvn`, and `scripts/verify.sh`'s `mvnw` reads the same file.
`tests/contract/workflow/maven_dependency_lock_test.sh` is the regression; the
evidence is in `specs/001-tor-route/evidence/T185-tests-first.json` and
THREAT-MODEL §5.9 (limits: remote SNAPSHOTs, metadata, no publisher
authentication, arm64 not build-confirmed).
