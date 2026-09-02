---
id: T085
title: 'Fix gofmt drift in bind/check_test.go + reconcile errortpl filename'
status: in-progress
created: 2026-07-05
last_updated: 2026-09-02
source: derived-from-T019-codereview  # not in tasks.md; filed from T019 codereview r1 F2 + T019 implementation-time gofmt-check discovery
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: true
files_budget: 4
privacy_critical: false   # paperwork-class: gofmt + a one-line contract-doc filename drift. Body mentions "routing" via the bind check's purpose, but this ticket does not touch any privacy-critical surface.
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/error-template.md §"Response body"
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T085: Fix gofmt drift in bind/check_test.go + reconcile errortpl filename

## Context

Two unrelated paper-cut defects surfaced during T019's `/start` validation
run. Neither is owned by T019; both are drive-by hazards if T019 had
"fixed" them inline. Filed together because both are small, low-risk, and
paperwork-class — batching into one ticket is cheaper than two parallel
onboarding contexts.

## Acceptance

1. **`data-plane/internal/bind/check_test.go` gofmt drift (from T012a).**
   The file is unformatted per `gofmt -l`. The diff is a 3-column
   alignment fix in a table-test struct literal (whitespace-only).
   Re-running `gofmt -w data-plane/internal/bind/check_test.go` and
   committing the result lands the fix. Post-fix, `gofmt -l
   data-plane/...` from the repo root returns zero matches.

2. **`specs/001-tor-route/contracts/error-template.md` filename drift.**
   Line 95 of the contract prose says:
   > "this matches the template literal stored as a Go string in
   > `data-plane/internal/errortpl/render.go`"

   T019 placed the literal in `data-plane/internal/errortpl/template.go`;
   `render.go` is the future home of the renderer (T048 / T071), not the
   literal. Amend line 95 to reference `template.go` for the literal and
   (optionally) note that `render.go` will hold the renderer.

3. `scripts/verify.sh` is GREEN. (No change to the verify log on this
   host because the go gate is SKIP — no Go toolchain. The fix lands
   correctly for CI / hosts with go.)

## Out-of-scope

- Any behavioral change to `bind.Check` or its test cases. This ticket
  is gofmt-only on that file.
- The renderer itself (`render.go`) — T048 / T071.
- Any change to `template.go` or `template_test.go` — T019 owns those.

## Notes

- Discovered during T019's `/start` validation:
  `gofmt -l data-plane/` returned `internal/bind/check_test.go`. T019
  did NOT touch it (surgical scope); T085 carries the fix.
- F2 from T019's codereview round 1 flagged the errortpl filename drift
  in the contract doc; T085 carries the amendment.
- Both fixes are paperwork-class. Codereview should be 1 round
  (APPROVE), redteam skips (`privacy_critical: false`).
- Run note (2026-09-02): acceptance 1 (gofmt fix) already landed as
  commit 2625f93 during the T019c run, after a Go toolchain install
  flipped the gofmt gate from SKIP to RED. Verified on this run's tree:
  `gofmt -l data-plane/` is clean. This ticket's diff therefore carries
  only acceptance 2 (the contract-doc amendment).

## Pre-flight self-check

```bash
python3 scripts/lint-ticket.py specs/001-tor-route/tickets/T085-*.md
```
