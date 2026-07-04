---
id: T001
title: 'Create the top-level directory skeleton from plan.md §"Project Structu'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T001
phase: "1: Setup (Shared Infrastructure)"
story: '-'
blocked_by: []   # TODO: derive from phase ordering + prose deps
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

# T001: Create the top-level directory skeleton from plan.md §"Project Structu

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Create the top-level directory skeleton from plan.md §"Project Structure" — `data-plane/`, `control-plane/{api,core,persistence,ui,runtime}/`, `extension/{background,options,popup,lib}/`, `proto/stargate/v1/`, `sidecars/tor/`, `compose/{,env}/`, `scripts/{,subcommands}/`, `tests/{contract/{tor,sidecar-proxy,error-template,torrc,socks5,control-grpc},integration,reproducibility}/` — using `.keep` placeholders where the directory is otherwise empty for this feature.

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
