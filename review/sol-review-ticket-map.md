# sol-review remediation map

This map records where each finding in `review/sol-review.md` is owned. New
ticket IDs follow finding severity/order; existing pending tickets are reused
where they already own the exact surface.

Implementation order and the temporary override to numeric ticket selection are
defined in `review/sol-review-implementation-plan.md`.

## Blockers

| Finding | Owner | Disposition |
|---|---|---|
| B1 Local installer/Compose identity | T088 | New remediation; T015/T016 history retained |
| B2 Tor starts before config | T089 → T087 | New spec amendment, then refined existing fix |
| B3 Cold-start plane coupling | T090 | New spec/contract remediation; stale implementation tickets blocked |
| B4 Unimplementable browser API contract | T091 | Constitution/spec amendment; T034b/T051/T054/T055 blocked |
| B5 Argon2 allocation DoS | T092 → T093 | New design amendment and tests-first contract |

## Major

| Finding | Owner | Disposition |
|---|---|---|
| M1 Token lifecycle inconsistency | T092 → T093 | Combined with B5; T035a/T035/T041/T044/T046 blocked |
| M2 Egress/Docker API/container hardening | T094 | New remediation of T019c/T015 topology |
| M3 Tor healthcheck cookie path | T087 | Existing pending ticket refined and blocked by T089 |
| M4 Green gate omits Go modules/skips | T076 | Existing pending ticket promoted to Foundational |
| M5 Incomplete inter-plane wire contract | T095 | New remediation of completed T022; T038/T045/T050 blocked |
| M6 Driver diverges from workflow | T096 | New workflow/tooling remediation |
| M7 Reproducibility/supply chain | T075b, T097, T098, T099, T081 | Existing tests/release refined; three focused remediations added |
| M8 False threat-model/docs claims | T082, T083, T088 | Existing tickets refined; direct doc corrections listed below |

## Additional weaknesses

| Finding | Owner | Disposition |
|---|---|---|
| A1 Persistence tests too shallow | T100 | New schema/repository contract remediation |
| A2 Log tests allow false assurance | T101 | New shared-scanner remediation |
| A3 Secret scanner misses tokens | T102 | New hook/CI/history remediation |
| A4 Shell quality outside green gate | T103 | New scoped shell gate |
| A5 Egress test lacks attribution | T034f | Existing pending ticket refined and blocked by T094 |

## Ticket-exempt documentation corrections applied

- Added `CODE_OF_CONDUCT.md` with a private reporting route.
- Replaced `<org>` GitHub placeholders with the repository's
  `zcat-app/stargate` origin.
- Reconciled CONTRIBUTING tool versions, current contract-test command,
  extension test runner, and no-build-step JavaScript policy.
- Renumbered the duplicate Error Prone/NullAway ticket from T081 to T104 so
  the release ticket retains its stable T081 identity.

No production code, Compose file, test implementation, or workflow script was
changed while filing this remediation set.
