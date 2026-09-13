---
id: "T142"
title: "Make agent execution-boundary claims demonstrable"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T096", "T139", "T156"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T096"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T142: Make agent execution-boundary claims demonstrable

## Context

Existing finding 20260727-010: the OpenCode adapter advertises denies that do not constrain its ordinary --auto implementation agent.

## Analysis

- **Must hold:**
  - Each reviewer receives its own immutable candidate copy, mount, process/PID namespace,
    temporary directory, home, network namespace and verdict channel; no reviewer can read a
    peer's mutable state or the live checkout (Principle VIII).
  - The candidate source is kernel-enforced read-only. The only writable persistent mount is that
    reviewer's private verdict directory; prompt instructions and OpenCode permission maps are
    defense in depth, not the isolation boundary.
  - Code review and privacy redteam each run two fresh GLM 5.3 contexts and one fresh Astra
    context in parallel. Astra effort is `medium` for correctness and `xhigh` for redteam. Every
    expected verdict is bound to the same driver snapshot and all approvals are required.
  - The launcher fails closed before model execution when Docker, a configured CLI, credentials,
    candidate sealing or containment setup is unavailable. It never falls back to the live tree.
  - Review records identify the actual reviewer id, tool, model, effort, candidate snapshot and
    capability limits; a role label alone is not evidence of independence (Principle VIII).
- **Gated:**
  - `tests/contract/workflow/review_task_test.sh` runs synthetic shell and Python prohibited-action
    probes in the real container boundary, compares namespace identities, and verifies private
    verdict import plus all-or-nothing failure behavior without real credentials.
  - `tests/contract/workflow/run_task_test.sh` requires every configured verdict, rejects stale or
    misidentified reviewers, and prevents a single canonical approval from advancing the ticket.
  - `scripts/verify.sh` discovers both workflow regressions; shell-quality and license gates cover
    the new launcher and configuration surface.
- **Residue:**
  - Provider access necessarily gives each CLI outbound network access and its own copy of the
    provider credential. The same-user CLI can potentially inspect its own credential; this
    ticket isolates that credential from peers and the host but does not claim a credential broker.
  - Separate reviewers share the host kernel, immutable host toolchain bytes and semantically
    identical candidate bytes. Container namespaces and dropped capabilities isolate mutable
    resources; this is process isolation, not separate hardware or provider-account independence.

## Acceptance

1. Trace the effective ordinary-agent configuration separately from reviewer-specific permissions and list actual credentials/files/process capabilities.
2. Define a reviewable containment policy or explicitly remove unsupported containment claims; do not call an arbitrary nonempty deny map a sandbox.
3. Add an effective-configuration regression and synthetic prohibited-action probes that include interpreter/shell alternatives; never use real credentials.
4. Require a concrete reviewed policy before changing permissions; preserve reviewer no-delegation/fail-fast rules and run scripts/verify.sh.
5. Replace conversational review dispatch with a fail-closed launcher that runs, in parallel and
   in separate Docker containers, two `zai-coding-plan/glm-5.3` reviewers and one
   `gpt-6-astra` reviewer for both code review and redteam. Pin Astra effort to `medium` for code
   review and `xhigh` for redteam in one checked-in review matrix.
6. Give every reviewer a separately materialized candidate, read-only source mount, private home,
   private temporary/output paths and private network/PID/mount namespace. Import verdict bytes
   only after all processes exit successfully and the live candidate still matches the handoff.
7. Make `run-task.sh` require and validate all three reviewer identities and verdicts before the
   next phase or commit; stale, missing, duplicate, malformed or peer-mismatched results fail
   closed and are never silently reduced to the legacy single-verdict gate.

### Required planning refinement


A policy decision alone does not satisfy closure: deliver the accepted implementation and
regressions, or create focused follow-up tickets and add them to T155 and affected consumers
before completing this ticket. No finding is accepted implicitly by documentation changes.

## Out-of-scope

Broadening existing permissions, weakening review gates, or exercising real exfiltration.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
