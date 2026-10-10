---
id: T110
title: 'Hermetic digest-agreement assertion for alpine:3.20 pins'
status: done
created: 2026-09-02
last_updated: "2026-10-10"
source: T107 review round 1 (APPROVE) RECOMMENDED-FOLLOW-UP #1
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T107", "T155", "T156"]
parallel: true
files_budget: 3   # complete change: substantive paths, ticket and STATUS
privacy_critical: true   # supply-chain pin-integrity surface (Principle IV), mirroring T107: test-only but the pin is the integrity anchor
complexity: low
risk: low
round_cap: 2
spec_refs: []
decision_refs:
  - SECURITY-DECISIONS.md (alpine:3.20 digest-pin rotation policy)
constitution_refs:
  - "IV: Every external component digest-pinned"
reviews: { round: 2, date: 2026-10-10, verdict: APPROVE, candidate_sha256: "17e1ae0931d81ebd5886acd55c0ddf312c170e663177cca827a9c26339b8ad8a", reviewers: "gpt-6-astra/high: APPROVE; gpt-6-luna/high: APPROVE", findings: "Both reviewers approved the exact candidate; no open findings." }
overrides:
  - "2026-10-10, user-authorized scoped verification: omit full scripts/verify.sh and VM; run the affected component checks only; preserve T110 red mutation evidence."
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T110: Hermetic digest-agreement assertion for alpine:3.20 pins

## Context

T107 pinned `alpine:3.20` by digest in two executable sites —
`STAT_IMAGE` in `tests/contract/stargate-cli/init_docker_test.sh` and
the `x-alpine` anchor in
`tests/contract/stargate-cli/fixtures/fixture-compose.yml` — and
recorded the pin in `SECURITY-DECISIONS.md`. Its rotation procedure
("update this const, the fixture anchor, and SECURITY-DECISIONS.md in
one PR") is enforced only by **review-time whole-tree grep**: the T107
entry explicitly attributes const/anchor agreement to review discipline
because the docker-gated suite cannot see a divergence — two different
valid pins both pull immutably, every runtime assertion still passes,
and the drift is silent. T107-r1 recommended closing that gap with a
cheap hermetic assertion (no daemon needed), explicitly deferred to a
follow-up ticket. Verified 2026-09-02: no test in the repo asserts the
three sites agree.

## Acceptance

1. A hermetic section at the TOP of
   `tests/contract/stargate-cli/init_docker_test.sh` — BEFORE the
   daemon self-SKIPs, so it runs on every host and in every Gate-4 run
   — extracts the digest literal from `STAT_IMAGE` and asserts via
   plain `grep -F` that (a)
   `fixtures/fixture-compose.yml` contains the same literal and (b)
   `SECURITY-DECISIONS.md` contains it (the entry's provenance + "The
   pin." lines). Any divergence FAILs, naming the file(s) that
   disagree.
2. Tests-first: the assertion is demonstrated red by temporarily
   rotating exactly one of the three literals, and green on the
   committed tree. (This acceptance IS the test; the "implementation"
   is the assertion.)
3. The docker-gated suite's runtime assertions and its self-SKIP
   semantics are unchanged; scripts/verify.sh stays green (the new
   section runs hermetically in Gate 4 even on docker-less hosts).

## Out-of-scope

Rotating the pin; tightening the `alpine:[0-9][^@]` gate pattern (its
tag-vs-digest blind spot belongs to whichever ticket owns that gate);
any change to fixture services or runtime pull behaviour.

## Implementation evidence

- The changed script was run with a temporary `docker` shim whose `info`
  command exits 1. It exited 0 after printing its existing
  `SKIP: docker daemon unreachable` notice, showing the digest agreement
  check passed before the daemon self-SKIP.
- In a temporary minimal git-root copy, the single fixture digest was
  rotated while `STAT_IMAGE` and `SECURITY-DECISIONS.md` stayed unchanged.
  The same script exited 1 and named
  `tests/contract/stargate-cli/fixtures/fixture-compose.yml` as disagreeing.
- `bash -n tests/contract/stargate-cli/init_docker_test.sh`,
  `python3 scripts/lint-ticket.py specs/001-tor-route/tickets/T110-hermetic-digest-agreement-assertion-alpine.md`,
  `scripts/regen-status.sh specs/001-tor-route`, and `git diff --check`
  all passed. The full `scripts/verify.sh` gate and VM were omitted under
  the scoped verification authorization above.
- Review trail: round 1 reviewed candidate
  `6b5d9497598bc1f8314240a22b8217e35e499043eaee4ed1d30a9c6b2e1dd8fb`;
  `gpt-6-astra/high` returned REWORK for one Minor (the multiline override
  was invalid YAML), and `gpt-6-luna/high` returned APPROVE. The override was
  corrected to one quoted scalar. On round 2, candidate
  `17e1ae0931d81ebd5886acd55c0ddf312c170e663177cca827a9c26339b8ad8a`
  received APPROVE from both `gpt-6-astra/high` and `gpt-6-luna/high`.
