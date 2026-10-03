---
id: T201
title: 'Durable STALE_CONFLICT marker: no changed push until recovery'
status: pending
created: 2026-10-03
last_updated: 2026-10-03
source: "T155 attempt 4 cumulative redteam (index tree 6e70e622): area 2 m3, survived falsification as Minor (E4: real TokenLoader against a model of the DP reload rule); maintainer chose the durable marker over disclosure, 2026-10-03"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 12  # ticket + STATUS.md + evidence/T201-tests-first.json (overhead);
                  # control-plane TokenLoader.java + TokenLoaderTest.java; runtime GrpcReloadChannel.java (+ its test);
                  # persistence migration V003 (+ its test); specs/001-tor-route/data-model.md; quickstart.md; THREAT-MODEL.md
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "II: Plane Separation"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/data-model.md
  - specs/001-tor-route/contracts/control-grpc.md
  - specs/001-tor-route/quickstart.md
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T201: Durable STALE_CONFLICT marker: no changed push until recovery

## Context

`STALE_CONFLICT` is terminal only for the running CP process: `GrpcReloadChannel.recordStale`
keeps it in memory, and data-model §1.8 "Read" lets changed `tokens.yaml` content propose
`generation + 1` with no conflict condition. After the CP state is restored from an older
backup and the DP refuses its generation as stale, each further changed `tokens.yaml` load
plus CP restart reserves the next generation. Enough of them overtake the DP's generation and
are accepted, carrying any credential the restored file still lists. Falsification ran this
with the real `TokenLoader` against a model of the DP reload rule (`server.go:114-121`): three
changed loads after a restore from a backup two generations old re-authorized a revoked token,
without the explicit rollback procedure. Each step is an operator edit and each refused step
shows `STALE_CONFLICT`, so this is not an automatic promotion (Constitution II), but it defeats
T159's must-hold ("the CP never promotes rejected stale credential content to a newer
generation") and the quickstart and THREAT-MODEL §5.15 do not warn about it.

## Analysis

- Must hold: once the DP refuses a candidate as stale, the CP durably records the conflict and
  makes no `ReloadTokens` push of changed content, and none can be accepted, until the
  documented stale-conflict recovery clears the marker; restarts do not clear it.
- Gated: CP unit tests (TokenLoader, GrpcReloadChannel), persistence migration test.
- Residue: host/root rollback of all trusted state stays outside the guarantee (Constitution II).

## Acceptance

1. Tests first: a TokenLoader/GrpcReloadChannel regression with restored-backup state, a stale
   reply, then N changed loads and a CP restart, in which no push is accepted (or none is made)
   until the recovery procedure clears the marker. Record RED on the current code with
   `scripts/test-first-evidence.py` (the falsifier's E4 probe is the reference red), then GREEN.
2. The CP persists the stale conflict durably (its SQLite state; a migration if needed) and
   consults it before any changed-content push, across restarts. Recovery option 1 (restore
   the newer CP state) and option 2 (explicit, operator-confirmed rollback) clear it as the
   quickstart describes; nothing else does.
3. `scripts/stargate status` keeps reporting `STALE_CONFLICT` while the marker is set (existing
   vocabulary; no history, timestamp or label recorded).
4. Update data-model §1.8, quickstart §"Stale-conflict recovery" and THREAT-MODEL §5.15 to
   match. THREAT-MODEL wording needs maintainer approval at T201 time: stop and return drafts
   before writing it.

## Out-of-scope

The DP's reload rule; DB-wipe recovery (T159); generation exhaustion by a compromised CP.
