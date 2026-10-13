---
id: T077
title: 'Run the first-time-human SC-001 quickstart walkthrough'
status: pending
created: 2026-07-04
last_updated: "2026-10-11"
source: tasks.md#T077
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T009", "T155", "T071", "T072", "T073", "T126", "T156", "T209", "T219"]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T077: Run the first-time-human SC-001 quickstart walkthrough

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> After T219, have a first-time human run the `quickstart.md` walkthrough in a private local or remote/virtual Linux x86_64 Mullvad Browser session, including on the existing VPS, with a fresh browser profile and clean git clone. Measure SC-001 wall-clock time from extension installation through token paste to rendered `.onion` page (<5 minutes), and record total clean-checkout setup duration separately in `tests/integration/quickstart_walkthrough.md`. Record venue, CPU and exact browser build/channel. Agent automation may provide functional evidence but cannot pass this human criterion. Depends on T219.

## Analysis

- **Must hold:** The first-time human follows the clean-profile enrollment and
  page-load path without weakening browser or authentication preconditions.
- **Gated:** T077 is a documented walkthrough; the source consistency and
  ticket checks cover its contract wording, while existing auth and browser
  gates remain separate.
- **Residue:** A source check cannot establish real human timing or successful
  page rendering. The T077 receipt must record both observations and disclose
  the exact browser channel.

## Acceptance

- A first-time human with a fresh supported Mullvad Browser profile follows
  only the quickstart. Record the actual venue, CPU and browser build/channel;
  the existing VPS may host a private remote/virtual session.
- Start the SC-001 wall clock at extension installation and stop at the rendered
  known `.onion` page after token paste; require under five minutes. Record
  the clean-checkout-to-render duration separately without attaching SC-001's
  threshold to it.
- Preserve the human observation and page-render evidence in
  `tests/integration/quickstart_walkthrough.md`. Agent automation is functional
  evidence only. Disclose Alpha-only coverage if the run uses Alpha.

## Out-of-scope

T034a owns the ten-minute DNS capture. SC-005 keeps its physical workstation
performance baseline. This ticket does not infer stable-browser support from
an Alpha result.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
T219 venue amendment, 2026-10-11: a private remote/virtual session is
permitted, but the first-time-human timer and threshold are unchanged.
