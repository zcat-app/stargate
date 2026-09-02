---
id: T084
title: 'Pin validation-image refs by digest across ticket prose'
status: done
created: 2026-07-05
last_updated: 2026-09-02
source: derived-from-T019b-redteam-r2  # not in tasks.md; filed from T019b redteam r2 Minor-1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []   # paperwork-class doc drift; canonical pin lives in data-plane/Dockerfile
parallel: true
files_budget: 4
privacy_critical: false   # doc-level residue in closed-ticket prose; no committed executable code pulls by tag. Lint PRIVACY-FLAG-MAYBE-MISSET fires because the body mentions "sidecar" (Dockerfile paths); this is a doc-only sweep, NOT a sidecar-contract change — privacy_critical is honestly false.
complexity: low
risk: low
round_cap: 2
spec_refs: []
decision_refs:
  - SECURITY-DECISIONS.md (digest-pinning rotation policy, Principle IV)
constitution_refs:
  - "IV: Every external component digest-pinned"
reviews:
  round: 1
  date: 2026-08-23
  verdict: ESCALATE→refine
  findings: "2 Major, 2 Minor — acceptance #2 zero-grep gate unmeetable as written (alpine:3.20 pulls in stargate-cli executable tests contradict §Context premise); acceptance #1 vacuous before==after (implementer sed artifact, remediated); refined per reviewer ESCALATION guidance"
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T084: Pin validation-image refs by digest across ticket prose

## Context

Filed from T019b's redteam round-2 sibling-hunt (Minor-1). T019b's
round-1 Major F2 fixed a Principle IV violation in T019b's own
validation command (`golang:1.26.3-bookworm` →
`golang:1.26.3-bookworm@sha256:252599…01c`). The round-2 sibling-hunt
found the SAME defect class in closed sibling artifacts — closed
ticket bodies and one handoff doc — where validation-command prose
references `golang:1.26.3-bookworm` BY MUTABLE TAG. This ticket sweeps
those prose-level references to match the canonical pin in
`data-plane/Dockerfile:36`.

Scope correction (2026-08-23 review round 1): the filing-time claim
that NO committed executable code pulls images by mutable tag was true
at filing but is stale — `tests/contract/stargate-cli/init_docker_test.sh`
(`STAT_IMAGE="alpine:3.20"`, docker-run) and
`tests/contract/stargate-cli/fixtures/fixture-compose.yml` (3 services)
now pull `alpine:3.20` by mutable tag. That is EXECUTABLE test code
needing a registry-resolved digest and docker-gated validation; it does
NOT belong in this doc-sweep ticket and is carved out to a follow-up
ticket (see §Out-of-scope). This ticket's defect class remains:
documentation-level validation-command snippets in historical /start-time
prose.

## Acceptance

1. The following locations amend their tag-only
   `golang:1.26.3-bookworm` reference to
   `golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c`
   (the same digest `data-plane/Dockerfile:36` carries — single source
   of truth):
   - `specs/001-tor-route/tickets/T019a-author-testsintegrationfakesocks5torgo.md`
     (validation-command prose).
   - `specs/001-tor-route/handoff-T009.md` (protoc-install snippet).
   - `specs/001-tor-route/tickets/T025a-contract-test-for-socks5-success-path-lo.md`
     (validation-command prose; surfaced by the round-1 sweep grep).
2. Whole-tree greps for actionable mutable-tag image references return
   ZERO matches outside `.git/`, `target/`, and the exclusions below.
   Patterns: `golang:[0-9].*bookworm[^@]` and `alpine:[0-9][^@]`.
   Exclusions (each verified individually — an exclusion must name a
   site that is EITHER a canonical pin OR non-actionable prose):
   - Canonical pins: `data-plane/Dockerfile`, `sidecars/tor/Dockerfile`,
     `control-plane/Dockerfile`,
     `tests/contract/tor/port_exposure_test.go` (`probeImage` const AND
     its rotation-procedure comment, which must name the tag to explain
     how to resolve the next digest), T019b's fixed §Acceptance #2
     (probeImage definition incl. its rotation-procedure sentence),
     §Acceptance #8 + §Notes.
   - Descriptive-prose class: `SECURITY-DECISIONS.md` illustrative TCB
     mentions; closed `redteam/findings/**` records (historical record,
     not editable without falsifying what was run); THIS ticket's own
     §Context / §Acceptance #1 before-side strings (they describe the
     defect being fixed and must stay tag-only to keep #1 non-vacuous).
3. (Optional, recommended) Amend `T019b` ticket prose to cross-ref this
   ticket from the round-1 F2 fix site so future readers see the sweep
   landed.

## Out-of-scope

- The canonical pin lives in `data-plane/Dockerfile:36` (and the two
  other Dockerfiles). T084 does NOT introduce a centralized
  `docs/dev/contract-tests.md` reference doc — that's a larger
  doc-structure refactor owned by a separate doc-architecture ticket
  if/when warranted.
- T084 does NOT touch `compose/docker-compose.local.yml` (canonical
  pin in Dockerfiles; the compose file is intentionally tag-free per
  T015's design).
- T084 does NOT touch `tests/contract/tor/port_exposure_test.go`'s
  `probeImage` const (already pinned).
- CARVED OUT (2026-08-23 review r1): digest-pinning `alpine:3.20` in
  `tests/contract/stargate-cli/init_docker_test.sh` (`STAT_IMAGE`) and
  `fixtures/fixture-compose.yml` (3 services). Executable contract-test
  code requiring a registry-resolved digest and docker-gated validation;
  file a follow-up ticket (suggested title: "Digest-pin alpine:3.20 in
  stargate-cli contract tests"). Until that lands, these two files are
  added to the §Acceptance #2 exclusion list.

## Notes

- Severity rationale: Minor in redteam's verdict because (a) no
  committed executable code is affected, (b) the prose snippets ran
  once at /start time and produced digest-pinned artifacts (go.sum
  h1 hashes), (c) the canonical pin in the Dockerfile is the actual
  promotion gate. Filing as a ticket rather than accepting inline
  because Principle IV's documentation discipline is what catches
  the next regression at review time.
- The same defect shape may exist for `debian:12-slim` (used by
  `sidecars/tor/Dockerfile` and `scripts/subcommands/init`) in any
  handoff / ticket prose; the whole-tree grep in §Acceptance #2
  should be extended to catch `debian:[0-9]*-slim[^@]` if found.
  (Round-1 sweep checked: all debian hits are canonical-pin comments
  or Dockerfiles — clean.)
- Filed alongside T083 (the other doc-hygiene sweep from T018
  redteam r3 INFO-1). T083 and T084 are independent; either can be
  driven first.
- Refine history: round-1 review (2026-08-23) returned ESCALATE;
  human chose `refine`. Acceptance rewritten per the reviewer's
  ESCALATION guidance (#1 non-vacuous before/after incl. T025a; #2
  enumerated exclusion classes + stargate-cli carve-out).

## Pre-flight self-check

```bash
python3 scripts/lint-ticket.py specs/001-tor-route/tickets/T084-*.md
```
