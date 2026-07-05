---
id: T084
title: 'Pin validation-image refs by digest across ticket prose'
status: pending
created: 2026-07-05
last_updated: 2026-07-05
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
reviews: {}
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

This is paperwork-class: NO committed executable code in the repo
pulls images by mutable tag (verified by whole-tree grep — `.sh`
scripts, `.yml` compose files, `.go` source all clean). The defect is
confined to documentation-level validation-command snippets in
historical /start-time prose.

## Acceptance

1. The following locations amend their `golang:1.26.3-bookworm`
   reference to `golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c`
   (the same digest `data-plane/Dockerfile:36` carries — single source
   of truth):
   - `specs/001-tor-route/tickets/T019a-author-testsintegrationfakesocks5torgo.md`
     (validation-command prose).
   - `specs/001-tor-route/handoff-T009.md` (protoc-install snippet).
   - Any other location surfaced by a fresh whole-tree grep for
     `golang:[0-9].*bookworm[^@]` or `alpine:[0-9][^@]`.
2. A whole-tree grep for the two patterns above returns ZERO matches
   outside `.git/`, `target/`, and the canonical pin locations
   (`data-plane/Dockerfile`, `sidecars/tor/Dockerfile`,
   `control-plane/Dockerfile`, `tests/contract/tor/port_exposure_test.go`'s
   `probeImage` const, T019b's now-fixed §Acceptance #8 + §Notes).
3. (Optional, recommended) Amend `T019b` ticket prose to cross-ref this
   ticket from the round-1 F2 fix site so future readers see the
   sweep landed.

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
- Filed alongside T083 (the other doc-hygiene sweep from T018
  redteam r3 INFO-1). T083 and T084 are independent; either can be
  driven first.

## Pre-flight self-check

```bash
python3 scripts/lint-ticket.py specs/001-tor-route/tickets/T084-*.md
```
