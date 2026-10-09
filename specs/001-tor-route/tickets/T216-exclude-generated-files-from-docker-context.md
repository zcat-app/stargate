---
id: T216
title: "Exclude generated files from the root Docker context"
status: done
created: 2026-10-09
last_updated: 2026-10-09
source: "T070 live-run preparation: observed 27 GiB root build context from .scratch (16 GiB) and target (11 GiB); implementation handoff specs/001-tor-route/.handoffs/T216-implementation-plan.md"
phase: "Foundation verification remediation"
story: "-"
blocked_by: []
parallel: false
files_budget: 3
files_scope:
  - .dockerignore
  - specs/001-tor-route/tickets/T216-exclude-generated-files-from-docker-context.md
  - specs/001-tor-route/STATUS.md
out_of_scope:
  - tests/integration/go.mod
  - tests/integration/route_down_stack_test.go
  - Dockerfile COPY inputs, Dockerfiles, or Compose build contexts
  - VM or live-stack execution and T070 route assertions
  - Docker image/cache pruning or cleanup of .scratch and target
privacy_critical: false
tests_first: []
test_for: []
constitution_refs: []
complexity: low
risk: low
round_cap: 2
spec_refs: []
decision_refs:
  - "T070 live-run preparation handoff: exclude checkout-generated data from root-context builds"
reviews: { round: 1, date: 2026-10-09, verdict: APPROVE, reviewers: "gpt-6-astra/high; gpt-6-luna/high", findings: "Both independent reviewers approved the same candidate." }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T216: Exclude generated files from the root Docker context

## Context

T070 live-run preparation found that root-context Docker builds were sending a
27 GiB checkout because the repository had no `.dockerignore`; the context
contains 16 GiB of `.scratch` evidence and 11 GiB of `target` artifacts. Keep
those generated and local-only paths out of the root context so the Tor
observer image can build from the actual checkout within the measured context
budget.

## Acceptance

1. Add root `.dockerignore` patterns for `.git`, `.scratch`, `target`, and
   root and nested generated `node_modules` directories. No explicit `COPY`
   input in the root-context DP, CP, Tor, or Tor observer Dockerfiles is
   excluded.
2. Build the Tor observer image with the Docker CLI using the repository root
   as context. The plain build output reports a transferred context below
   256 MiB.
3. Regenerate `specs/001-tor-route/STATUS.md` from ticket frontmatter.

## Out-of-scope

This ticket changes only the root ignore rules, its ticket, and generated
status. The already-staged T070 candidate and its route assertion remain
untouched. It does not run a VM or live stack, prune Docker data, or delete
local evidence and build artifacts.

## Notes

The root-context Dockerfiles use explicit `COPY` paths. The ignore patterns
remove repository metadata and generated/local output while preserving those
source inputs.
