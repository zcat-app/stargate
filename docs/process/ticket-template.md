---
id: T-NNN                       # Stable ticket id. Matches the tasks.md entry it derives from. Never reused.
title: <imperative title, ≤ 70 chars>
status: pending                 # pending | in-progress | in-review | escalated | done | deferred
created: <YYYY-MM-DD>           # Set on first save; never edited afterwards.
last_updated: <YYYY-MM-DD>      # Updated by the driver on every status transition.
source: tasks.md#T-NNN          # Anchor back into the spec-kit plan. tasks.md is regenerated
                                # by /speckit-tasks; the tickets/ directory is NOT — edits here
                                # survive a tasks.md regeneration. If tasks.md changes the
                                # underlying task, file a decompose/refine rather than hand-editing.
phase: <Setup | Foundational | Core | Integration | Polish>   # from tasks.md phase header
story: <US1 | US2 | US3 | ->    # from tasks.md [USx] marker, or '-' for non-story work.
blocked_by: []                  # List of T-NNN ids that must be `done` before this can start.
                                # Derived from tasks.md phase ordering + explicit "Depends on T..."
                                # prose + the `tests_first:` field below (T096). Empty for Phase-1
                                # tasks with no prose deps.
parallel: true                  # `true` mirrors the tasks.md [P] marker; means "files_scope is
                                # disjoint from other in-flight [P] tickets, so a worktree may run
                                # this in parallel". `false` → serialises.
files_budget: 8                 # Numeric upper bound on files the diff may touch (incl. tests).
                                # stargate-codereview FAILs SCOPE-DRIFT-CHECK if exceeded.
                                # Count every touched path, including this ticket, specs/ and new files.
files_scope:                    # OPTIONAL path/glob list. When present, the reviewer ALSO runs
                                # the negative-space check (files in scope NOT touched). Omit when
                                # the budget is purely numeric.
  # - data-plane/internal/bind/**
  # - data-plane/internal/bind/*_test.go
out_of_scope:                   # Explicit list of paths/features this ticket MUST NOT touch.
                                # Subtickets of an umbrella SHOULD list the umbrella's integration
  # - tests/contract/**           # test files here.
  # - compose/**

# --- Stargate-specific flags (drive the autonomy dial) ----------------------
#
# These two flags are what make the Constitution machine-checkable per ticket
# instead of relying on the agent remembering to re-read 23KB of principles.

privacy_critical: false         # `true` if the task touches ANY of: DNS resolution, routing
                                # decisions, header handling, authentication, sidecar contracts,
                                # bind-safety, or any other Constitution-Principle-I/III surface.
                                # When `true`: tests MUST be written first (Principle VII, no AI
                                # exception); `stargate-redteam` runs before commit; autonomy is
                                # gated — even a green verify.sh is not sufficient to auto-commit.
                                # When `false`: standard review path; autonomy OK on green verify.
                                # Source: tasks.md task body — most Phase-3+ tasks are `true`.
tests_first: []                 # Principle-VII directed metadata (T096 / sol-review M6). List the
                                # test ticket ids that MUST be `done` before this implementation
                                # can start. scripts/derive-deps.sh adds them to blocked_by;
                                # scripts/lint-ticket.py rejects a privacy_critical impl whose
                                # named test is not a blocker (i.e. runnable before its test).
                                # Empty for document tickets or regressions authored first inside the same ticket.
test_for: []                    # Reverse view: on a TEST ticket, the impl id it gates. Consumed
                                # by derive-deps.sh the same way as tests_first (adds this test to
                                # the named impl's blocked_by). Use one or the other, not both.
constitution_refs:              # Which Constitution principles this ticket carries. Used by
                                # stargate-codereview to scope its check. Cite by number+name.
  # - "I: Dumb router"
  # - "III: No outbound except routed request"
  # - "VII: Tests-first for privacy-critical paths"

complexity: low                 # low | medium | high. `high` triggers the plan-writer subagent
                                # at start (a fresh-context planner drafts an outline sidecar at
                                # specs/.handoffs/T-NNN-OUTLINE.md before any code is written).
risk: low                       # low | medium | high. `high` triggers a commit-time verify.sh
                                # re-run rather than trusting the prior green log.
round_cap: 2                    # Default 2 rework rounds. May be 3 ONLY for complexity: high OR
                                # risk: high. Hitting the cap fires the escalation menu — see
                                # .specify/memory/review-loop.md.

spec_refs:                      # The spec sections this ticket implements. Anchors the "why".
                                # Required for any task with acceptance derived from spec.md.
  # - specs/001-tor-route/spec.md §"FR-010"
  # - specs/001-tor-route/contracts/control-grpc.md §"Socket topology"
decision_refs:                  # Decision IDs from research.md / plan.md this ticket carries.
  # - research.md §1
  # - plan.md §"Plan-level tensions" #10

# --- Lineage (populated by the driver skill during escalations; usually empty) ---
#
# stargate adopts the infochat lineage model: when a ticket is decomposed /
# deferred / spec-amended, the relationship is recorded here so a stale child
# doesn't get lost. Git log carries refine/override history (no YAML
# accumulation for those).

decomposed_from: T-NNN          # The parent ticket this was split out from.
replaces: T-NNN                 # The prior ticket this rewrites (refine produced a new id).
replaced_by: T-NNN              # Set on the OLD ticket when refine produces a new one.
deferred_on: T-NNN              # The blocker ticket this is paused on (if status: deferred).
deferred_reason:                # One of: decomposed | blocked-on-new-ticket | spec-amend.
spec_amend_for: specs/000-architecture/spec.md §4.3   # When this ticket exists to amend the cited spec.
spec_amend_parent: T-NNN        # The implementation ticket waiting on this amendment to land.
remediates: T-NNN               # Set on a remediation ticket created from a redteam finding on a
                                # done ticket. The done ticket is NEVER amended; this ticket
                                # carries the fix (one-commit-per-ticket invariant).

# --- Dynamic (populated by the driver skill; start empty) ---
#
# `reviews` and `clarity_check` carry the LATEST entry only — git log is the
# audit trail for prior rounds.

reviews: {}                     # Latest review only: {round, date, verdict, findings, diff_stats}
overrides: []                   # Populated on `override` escalations.
aborted_attempts: []            # Populated by `abort`.
reopens: []                     # Populated by `reopen`.
redteam_findings: []            # Populated by `stargate-redteam`; one entry per finding.
clarity_check: {}               # Populated by `start` (clarity pre-flight).
---

# T-NNN: <title>

## Context

One paragraph. Why does this ticket exist? What does completing it unlock? Cite
the parent feature spec (`specs/NNN-feature/spec.md`) and the matching
`spec_refs:` entry as the contract.

For tasks derived from tasks.md (the common case), the Context is a one-line
condensation of the tasks.md entry — *not* a copy. tasks.md remains the
authoritative source for the full task body; this section is the skimmable
summary that lets `scripts/next-task.sh` and a human reviewer see at a glance
what the ticket is for.

## Analysis

*(Required when `privacy_critical: true` OR `complexity: high`; omit otherwise.)*

The property map from the analyze gate (`docs/process/analysis.md`), grounded in
the code and the cited spec sections:

- **Must hold** — the invariant-altitude properties this change must satisfy.
  For privacy-critical tasks, this is where Constitution principles land as
  concrete properties ("every bind(2) call is preceded by the loopback check",
  "no destination hostname appears in any log line", etc.).
- **Gated** — which of those properties `scripts/verify.sh`, contract tests,
  or static analysis already catch fail-closed (no standing human vigilance
  needed).
- **Residue** — the properties **no gate catches**. Each residue item must map
  to a named test/guard in §Acceptance, and scopes the `stargate-redteam` pass.
  Residue is exactly what redteam exists to hunt; an empty residue means the
  change sits entirely inside the mechanical envelope.

## Acceptance

Mirror the YAML `acceptance:` list in prose so a human understands "done"
without parsing YAML. **This is the only section that pins behavior** — §Notes
is non-binding. Each item is one of:

- A **named test** the diff must add and pass (preferred for privacy-critical
  tasks — Constitution Principle VII requires test-first).
- A one-line **behavioral assertion** the reviewer can check against the diff
  or the verify.sh output.
- A **runnable command** (e.g. `scripts/verify.sh` is green; the named contract
  test under `tests/contract/...` passes).

Avoid grep-cardinality acceptance ("grep -cE '...' returns ≥N matches"). The
test passing is the only ground truth.

## Out-of-scope

Prose explanation of what `out_of_scope` covers and why. The reviewer uses this
to judge scope-drift. Be specific about what is *intentionally* not done here
so the developer doesn't accidentally do it. If this ticket modifies a
pre-existing test, name it here with the new expected behavior — unauthorized
test edits are test-integrity violations.

## Notes

Free-form, non-binding rationale: design pointers (`plan.md §X`), adjacent code
this should match, alternatives considered, big-picture concerns. If a sentence
here describes behavior the diff must implement, move it to §Acceptance.

---

## Evidence and decision closure

Privacy-critical implementations with empty `tests_first` still require a named spec-derived
regression and red-before-green evidence in Acceptance. Never make a permanently red standalone
test ticket a required done dependency; use the workflow's combined regression/fix refinement.
Design tickets must require implementation children and closure/consumer blockers in Acceptance.
Document amendments require consistency checks and independent review, not fabricated runtime tests.
Use current constitution references; acceptance of a finding cannot waive its guarantees.

## Pre-flight self-check (author-side)

Before running `scripts/next-task.sh` against this ticket (or starting work on
it), run `scripts/lint-ticket.py` against it:

```bash
python3 scripts/lint-ticket.py specs/NNN-feature/tickets/T-NNN-*.md
```

The linter catches mechanical authoring errors at author-time so they don't
cost a clarity-subagent round.
