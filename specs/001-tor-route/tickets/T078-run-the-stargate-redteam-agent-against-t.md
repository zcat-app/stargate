---
id: T078
title: 'Run the `stargate-redteam` agent against the completed feature branch '
status: pending
created: 2026-07-04
last_updated: 2026-10-16
source: tasks.md#T078
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by:
  - "T208"
  - "T203"
  - "T009"
  - "T155"
  - "T034a"
  - "T034f"
  - "T064"
  - "T065"
  - "T066"
  - "T067"
  - "T067a"
  - "T067b"
  - "T070"
  - "T070a"
  - "T070b"
  - "T071"
  - "T072"
  - "T073"
  - "T075"
  - "T077"
  - "T079a"
  - "T080"
  - "T081"
  - "T109"
  - "T110"
  - "T111"
  - "T112"
  - "T114"
  - "T119"
  - "T120"
  - "T121"
  - "T123"
  - "T124"
  - "T126"
  - "T132"
  - "T134"
  - "T135"
  - "T136"
  - "T137"
  - "T138"
  - "T139"
  - "T160"
  - "T141"
  - "T142"
  - "T143"
  - "T144"
  - "T145"
  - "T146"
  - "T147"
  - "T148"
  - "T149"
  - "T150"
  - "T151"
  - "T152"
  - "T153"
  - "T156"
  - "T157"
  - "T158"
  - "T159"
  - "T161"
  - "T189"
  - "T190"
  - "T191"
  - "T196"
  - "T197"
  - "T198"
  - "T199"
  - "T200"
  - "T201"
  - "T204"
  - "T205"
  - "T206"
  - "T209"
  - "T202"
  - "T212"
  - "T215"
  - "T218"
  - "T220"
  - "T222"
  - "T223"
  - "T224"
  - "T225"
  - "T226"
  - "T227"
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: false
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

# T078: Run the `stargate-redteam` agent against the completed feature branch 

## Binding October16 dependency reconciliation

Retain direct blockers for the new source/platform/native owners and existing wider cadence
and product repairs. A completed source-only T209 or T223 cannot bypass native A2/A7 or broader
T202/T212/T215 evidence. This edit changes prerequisite metadata only: T078/T079 execution remains
outside the authorized steps10–14 scope. Keep the existing cumulative reviewer fleet and all
actual completed-candidate evidence requirements; no review is launched by this maintenance.

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical task summary (current acceptance/dependencies above govern):**
>
> Run the `stargate-redteam` agent against the completed feature branch (Principle VIII); findings either resolve in-feature or land in `SECURITY-DECISIONS.md` (T017) with explicit acceptance rationale.

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

### Required planning refinement


Review the completed candidate, including all foundation follow-ups, release machinery and
live acceptance evidence. T155 is only the earlier foundation checkpoint. Record snapshot,
reviewer independence, executed/skipped checks and finding dispositions. Add newly created
remediation tickets as blockers before claiming completion; rerun affected evidence after fixes.

Reviewer fleet (maintainer decision 2026-09-29): run the Opus `stargate-redteam` agent and, on
the same bound snapshot, separate Astra (Codex `gpt-6-astra`, high) and GLM-5.3-Flash (OpenCode,
xhigh/native `max`) cumulative passes, each in a fresh native session without implementation
rationale, dispatched by a driver script rather than a hand-invoked CLI. Record each reviewer's
actual model identity as reported by its CLI; a reviewer that fails, falls back to another model
or cannot be identified fails closed. Union and dedupe findings; one reviewer's silence never
dismisses another's finding. Adding that cumulative dispatch path is in scope for this ticket.

Decide whether the Tor sidecar counts as a "compromised application process" for the
Constitution III actor/destination matrix (Tor's LAN/host reach through `stargate-egress`; T155
attempt-4 redteam, area 3 M1, narrowed to disclosure residue, T197 item 5).

This ticket owns release-cadence item R-7 of `specs/001-tor-route/live-e2e/README.md`
section 4 (routed IPv6 egress, LAN and VPS profiles, physical NIC and hypervisor behaviour):
it is either run on the release candidate and recorded with snapshot and evidence, or
dispositioned by the maintainer here; it is never recorded as PASS without a run
(maintainer, 2026-10-05, "R-7 to T078 (Recommended)"; T155 Acceptance 1 closure re-check).

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T173 renderer dependency refinement

T071 owns the consolidated T068/T069 tests and renderer implementation. Retain T071 as
the blocker; the superseded deferred test tickets must not independently block this consumer.

2026-10-03 observer-only continuation: T203 blocks this cumulative review and T155; the other newly surviving findings remain unresolved and no waiver is implied.

## Approved dependency reconciliation — 2026-10-03

The maintainer approved the remaining foundation scope after T203. T204 owns CP listener enforcement, T205 owns persistent hardening-record removal and absorbs T117, and T206 owns the DNS capture-integrity Minor. All three block this release review; no finding is waived by filing an owner.
