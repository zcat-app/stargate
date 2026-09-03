---
id: T114
title: 'Wire staticcheck + gosec into the Go workspace gate (data-plane TCB)'
status: pending
created: 2026-09-03
last_updated: 2026-09-03
source: hand-authored   # Raised by T043's round-1 codereview
                        # (RECOMMENDED-FOLLOW-UP, target/runs/T043.verdict):
                        # no scanner-class gate exists anywhere in the repo.
                        # See docs/process/workflow.md §"Pure-doc commits" —
                        # this is a code change, so it's a ticket.
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []          # T076 (the go-workspace-gate this extends) is done.
parallel: true          # Extends scripts/go-workspace-gate.py + tool deps;
                        # no other open ticket touches that file.
files_budget: 8
files_scope:
  - scripts/go-workspace-gate.py
  - data-plane/go.mod      # tool directives (pinned staticcheck + gosec)
  - data-plane/go.sum
out_of_scope:
  - control-plane/**      # static-analysis for the Maven reactor is
                          # T104's (Error Prone + NullAway), already done.
  - extension/**
  - tests/**              # contract/integration suites are not scanner
                          # subjects; the gate already runs their go tests.
  - data-plane/** source  # production source changes only as initial
                          # triage output (fix-or-waive); no feature work.
  - scripts/verify.sh     # the gate script is already discovered and
                          # invoked by verify.sh (go-workspace hook); no
                          # new entrypoint.

# --- Stargate-specific flags ---
privacy_critical: false  # Tooling wiring, not a privacy surface — same call
                         # as T104. The MOTIVATION is privacy (the data plane
                         # is the privacy TCB; see Context), but the diff has
                         # no runtime behaviour. Redteam N/A.
constitution_refs:
  - "I: Dumb router (gosec's value here is mechanical: it hunts the classes
     of memory/crypto/permission slips a dumb router must not grow)"
  - "VII: Tests-first / fail-closed gates (this moves a class of defects
     from reviewer-vigilance residue into gated-by-verify.sh)"
complexity: low          # Design is settled: extend the existing discovered
                         # gate with two pinned tools; no new entrypoint.
risk: low                # CI/local gate only; ship behaviour unchanged.
round_cap: 2

spec_refs:
  - "docs/process/analysis.md §"Gated" (names staticcheck + gosec as the
    data-plane gates verify.sh is *supposed* to catch fail-closed — the
    premise this ticket makes true)"
  - "CONTRIBUTING.md §"Working doctrine" (falsify-before-publishing: a
    green verify.sh must mean what it says)"
  - "specs/001-tor-route/tickets/T043-implement-data-planeinternallistenerconn.md
     §Analysis §Residue (the finding + residue record that raised this)"
decision_refs:
  - "specs/001-tor-route/tickets/T104-wire-error-prone-nullaway-into-control.md
     (the control-plane twin: same rationale shape, same fail-closed
     integration pattern, same triage-before-landing rule)"
  - "specs/001-tor-route/tickets/T076-wire-all-six-v1-contract-test-directorie.md
     (the gate this ticket extends; its discover-don't-enumerate and
     verdict-rules contract must be preserved)"

reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T114: Wire staticcheck + gosec into the Go workspace gate (data-plane TCB)

## Context

The repo's Go gate (`scripts/go-workspace-gate.py`, T076) runs `go vet` +
`go test -json` over every workspace module — and nothing else. No
staticcheck and no gosec invocation exists anywhere (scripts/, CI, Makefiles:
zero hits, verified by T043's round-1 review). The gap is not academic:

- `docs/process/analysis.md` tells every ticket author that staticcheck and
  gosec gate the data plane fail-closed. T042 and T043 both wrote §Gated
  bullets citing that premise; T043's reviewer caught it as an overclaim
  (the repo's own falsify-before-publishing doctrine, applied to the docs).
- The data plane is the privacy TCB (Principle I): the inbound-framing
  code (T042/T043) is exactly where gosec's classes (unhandled errors,
  weak crypto misuse, file-permission slips) and staticcheck's classes
  (logic/usage bugs `go vet` cannot see) apply.
- The gate is born WITHOUT the scanners that the ticket model has been
  claiming as "gated" — residue that several tickets believe is already
  promoted is not.

The control-plane twin is already landed: T104 wired Error Prone + NullAway
into the Maven reactor on the same rationale. This ticket closes the Go side.

Precedent for the gate's shape: T076's `go-workspace-gate.py` discovers
modules from `go.work` and owns the verdict rules (SKIP-never-PASS,
cadence tags). This ticket extends that script, preserving its contract.

## Analysis

Quick pass (`privacy_critical: false`; the substantive points, no formal
property map):

- **Must hold:** both scanners run at every verify.sh invocation
  (hermetic, local — no new network egress beyond pinned module download,
  same as any Go build); scanner findings fail the gate (fail-closed,
  T076's verdict-rule spirit); tool versions are pinned (repo culture:
  byte-reproducible builds — a floating `latest` scanner is a
  non-reproducible gate); the tree lands with ZERO outstanding unwaived
  findings (a born-red gate gets disabled within a week — triage is part
  of this ticket, not a follow-up); T076's discover-don't-enumerate and
  SKIP-accounting behaviour is unchanged.
- **Gated:** verify.sh GREEN with the gate log proving both scanners
  executed (not SKIP) — the acceptance command below is self-evidencing.
- **Residue:** staticcheck/gosec catch a *class*, not a proof — the
  contract suites (T023–T028, T026/T027) remain the byte-level privacy
  gates; scanner silence is defence-in-depth, not a privacy property.

## Acceptance

1. **Pinned tools, discovered invocation**: staticcheck and gosec are
   version-pinned Go tool dependencies (e.g. `tool` directives in
   `data-plane/go.mod`; exact mechanism per current Go tooling convention —
   pinned by version, never floating) and are invoked BY
   `scripts/go-workspace-gate.py` (not a side script), so every existing
   verify.sh consumer gets them for free.
2. **Fail-closed integration**: scanner findings produce the same outcome
   class as a `go vet` failure — gate FAIL with the offending module named.
   A scanner that cannot run (toolchain missing) SKIPs loudly per the
   gate's existing SKIP discipline — it must never be silently absent
   from a green log. Scope: the data-plane module is the motivating
   surface; extending to all discovered Go modules is preferred if
   noise-free, but data-plane-first is acceptable if other modules'
   findings would force a waive-fest (record the choice + rationale).
3. **Triage-before-landing**: at this ticket's review, a full run reports
   zero findings on the data plane — each initial finding either fixed in
   this ticket or waived with a written, code-adjacent rationale
   (inline `//lint:ignore <reason>` style per tool convention, or the
   gate's config — chosen mechanism documented in the ticket §Analysis).
   Waivers name the principle/spec reason, not "noisy".
4. **No false gates remain**: `grep -rn "staticcheck\|gosec"
   scripts/ docs/process/analysis.md` now reflects reality — the gate
   wires them (or analysis.md §"Gated" is amended to match whatever this
   ticket actually lands). The T043-era overclaim class must not reappear.

### Runnable command

```sh
bash scripts/verify.sh && \
  grep -iE "staticcheck|gosec" target/verify.log
```

verify.sh RESULT: GREEN **and** the log shows both scanners executed with
zero outstanding findings.

## Out-of-scope

- Control-plane static analysis — T104, done.
- Fixing feature-level findings beyond initial triage — triage fixes must
  be mechanical (the tree today is small); anything substantive becomes a
  follow-up ticket.
- Contract/integration test suites — already gated by T076's test pass.
- New CI workflows — verify.sh is the single green gate (AGENTS.md); the
  scanners ride inside it.

## Notes

Provenance: T043 round-1 codereview, APPROVE-WITH-FIXES,
RECOMMENDED-FOLLOW-UP + FIX ITEMS residue (2026-09-03). Hand-authored per
docs/process/ticket-template.md; T104 is the structural precedent.
