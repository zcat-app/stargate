---
id: T076
title: 'Wire **all six v1 contract-test directories**'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T076
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
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

# T076: Wire **all six v1 contract-test directories**

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Wire **all six v1 contract-test directories** — `tests/contract/{tor,torrc,socks5,error-template,control-grpc,sidecar-proxy}/` — into CI as **required** checks for any PR that touches `compose/docker-compose.local.yml`, `data-plane/`, `control-plane/`, `proto/stargate/v1/`, or `sidecars/` (FR-016, Principle IV). The workflow MUST also run the `extension/run-tests.sh` discovery script (Node 20 LTS pinned per research.md §10; picks up T034b–T034e) on any PR touching `extension/`. The CI config lives in `.github/workflows/contract.yml` (GitHub Actions; matches constitution §VI's commitment to GitHub hosting with a Codeberg mirror as a v1.5+ consideration). Implementation note: glob `tests/contract/*/` rather than enumerating fixed names, so a future feature adding `tests/contract/<surface>/` extends the gate without needing to amend this workflow. PR-time integration tests under `tests/integration/` are also wired into the same workflow — at minimum T034 (DNS-leak gate, explicitly labelled PR-time in its description) and T079a (concurrent-connects regression gate; explicit PR-cadence). Integration tests explicitly labelled release-tag-cadence in their own task description (T034a, T034f, T070a) are excluded; tests with no explicit cadence label are an infra decision left to the implementer at workflow-authoring time (in practice: PR-time iff the test does not depend on the live Tor network).

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
