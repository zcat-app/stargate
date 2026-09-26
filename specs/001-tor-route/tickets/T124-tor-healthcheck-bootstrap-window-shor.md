---
id: T124
title: 'Allow bounded cold-bootstrap time during init'
status: in-review
created: 2026-09-07
last_updated: 2026-09-26
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T139", "T134", "T138", "T156", "T162", "T164", "T165", "T152", "T174", "T177"]
parallel: false
files_budget: 15
files_scope:
  - specs/001-tor-route/tickets/T124-tor-healthcheck-bootstrap-window-shor.md
  - specs/001-tor-route/STATUS.md
  - specs/000-architecture/spec.md
  - specs/001-tor-route/spec.md
  - specs/001-tor-route/plan.md
  - specs/001-tor-route/quickstart.md
  - specs/001-tor-route/contracts/torrc.md
  - THREAT-MODEL.md
  - scripts/subcommands/init
  - scripts/stargate
  - tests/contract/stargate-cli/init_readiness_test.sh
  - tests/contract/stargate-cli/init_test.sh
  - data-plane/cmd/tor-observer/main_test.go
  - specs/001-tor-route/evidence/T124-tests-first.json
  - reviews/T124/README.md
privacy_critical: true
tests_first: []
constitution_refs:
  - "II: Plane Separation"
  - "III: Privacy-Preserving by Construction"
  - "V: Honest Threat Model"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: medium
risk: "medium"
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §9.1 steps 4–7 and §9.2
  - specs/001-tor-route/spec.md §User Story 1 and FR-012
  - specs/001-tor-route/contracts/foundation-boundaries.md §Deployment and authority
  - specs/001-tor-route/contracts/torrc.md §Invariants
  - THREAT-MODEL.md §5.18
decision_refs:
  - specs/001-tor-route/tickets/T152-resolve-operational-audit-contract.md
  - specs/001-tor-route/tickets/T174-migrate-live-observer-operational-checks.md
  - reviews/T161/README.md
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T124: Allow bounded cold-bootstrap time during init

## Context

Originally filed from T059's live run #3 (2026-09-07), this ticket proposed making
Tor's Docker healthcheck pass on cookie authentication before full bootstrap. T152
subsequently disabled Docker healthchecks and diagnostic retention under Constitution III.
The installer now invokes the isolated observer's fixed `--check-ready` operation and
requires authenticated bootstrap progress of 100%. T174 migrated live consumers to that
current readiness boundary. The original Dockerfile change no longer applies.

The remaining problem is the installer's 60-second default readiness budget. T161 recorded
a cold bootstrap that spent about 130 seconds loading descriptors before completing; T165's
historical deployed validation used a 300-second installer override. These observations
support a larger bounded operator wait, but establish neither a root cause for T160's
preserved failures nor a guaranteed bootstrap duration.

## Authorized refinement (2026-09-26)

The maintainer requested exploration without bending the Constitution, then authorized
refinement to retain authenticated READY and allow bounded cold-start time. The selected
default is 300 seconds with the existing operator override. Architecture §9.1's 60-second
Docker-health/log-tail wording and affected active readiness references must be reconciled
with T152/T174 in the reviewed implementation; no constitutional amendment is authorized.
The ticket remains pending. Its prior clarity PASS described the superseded proposal and
has been cleared for a new grounding pass. The 15-file scope includes operator quickstart
instructions that still recommend now-disabled raw logs, plus documentation, tests,
durable evidence, this ticket and the generated status board.

## Analysis

- **Must hold:** installer success requires all four services running and an authenticated
  observer result of READY. A valid cookie or open control socket alone, incomplete bootstrap,
  missing/rejected credentials, malformed replies and an unavailable observer cannot produce
  success. Preserve finite output, the fixed Tor command sequence, the four-second query bound,
  CP credential/socket isolation and advisory-only CP health for DP routing (II/III).
- **Must hold:** success occurs as soon as READY is sampled within the configured budget.
  Expiry returns 40 and leaves containers/data intact. Preserve the documented in-flight
  sample/retry overrun; do not claim a hard deadline for every Docker operation. Docker
  healthchecks and retained raw diagnostics remain disabled (III/V).
- **Gated:** current installer tests reject NOT_READY, UNAVAILABLE and exec failure despite
  running containers. Observer tests cover finite tokens, malformed replies, caller
  authentication and blocked-cookie I/O. Extend coverage to the real default, delayed READY,
  explicit overrides and missing/rejected Tor-cookie authentication.
- **Residue:** fixtures cannot establish public Tor availability or current production-stack
  cold readiness. Acceptance requires a fresh-volume Local run with its limitations stated.
  Historical evidence and a green hermetic gate cannot substitute for it. Five minutes is
  an operational budget, not an availability guarantee.

## Acceptance

1. Before changing the installer, extend `init_readiness_test.sh` with a deterministic clock
   and the real `wait_healthy` function/default initialization. A `delayed_ready_default`
   case keeps all services running, returns NOT_READY until simulated second 90, then READY.
   It must fail against the current 60-second default and pass after the change without
   overriding the default in the test. Record the same probe's red/green results through
   `scripts/test-first-evidence.py` in `evidence/T124-tests-first.json`.
2. Set the installer default to 300 seconds and synchronize CLI help. Require early success
   when READY arrives; preserve an explicit shorter/longer operator override. Named cases
   `ready_immediately`, `delayed_ready_default`, `short_override_timeout`,
   `long_override_delayed_ready`, `never_ready_timeout`, `unavailable_timeout` and
   `exec_failure_timeout` exercise these behaviors without real sleeps. Expiry returns 40,
   never tears down containers or deletes state, and never prints a successful status table.
   Preserve the existing caller-stdin isolation assertion.
3. Preserve READY/NOT_READY/UNAVAILABLE meanings and the four-second observer query bound.
   Add `TestInstallerReadinessMissingCookie` and `TestInstallerReadinessRejectedCookie`:
   missing or malformed cookie files and a rejected 32-byte cookie cannot return exit 0;
   rejected authentication must not be followed by GETINFO. Retain incomplete-bootstrap,
   malformed-reply and blocked-cookie-I/O tests. Write these regressions before implementation;
   tests for already conforming behavior are retrospective guards, not fabricated red evidence.
   A discovered observer implementation defect requires a scoped follow-up; this ticket
   authorizes no observer production change.
4. Reconcile architecture §9.1 steps 4–7/§9.2, affected feature-spec health references,
   torrc-contract healthcheck prose, CLI/test and quickstart descriptions and
   THREAT-MODEL §5.18 with current
   observer readiness and the new default. Describe one readiness window after Compose
   startup, not 300 seconds separately per sidecar. Remove affected active instructions to
   wait for Docker health or retrieve raw log tails. Preserve exact torrc bytes, the finite
   observer protocol and existing privacy boundaries. Update the plan's Constitution Check
   with scoped consistency findings and pending/executed evidence; do not rewrite historical
   reviewed records or claim broader architectural compliance.
5. On a disposable host suitable for the supported Local topology, use fresh project volumes
   and supported `scripts/stargate init` with no readiness-timeout override or preseeded Tor
   state. Record candidate identity, environment and finite outcome in `reviews/T124/README.md`;
   success must include the observer's authenticated READY result. Do not induce slow public
   network conditions or add destination probes. The deterministic test establishes delayed
   readiness handling; the live run establishes current cold-stack compatibility. Retain
   failed attempts honestly. Unavailable or failed required live evidence keeps the ticket
   incomplete; do not alter independent live-test deadlines, seed state, weaken assertions
   or relabel T160/T161 evidence to obtain PASS.
6. Run `bash scripts/verify.sh` on the exact candidate, record executed/skipped coverage,
   and obtain the normal two independent reviewer verdicts before the driver commits.
   Regenerate STATUS from frontmatter; T155 remains blocked on T124 until delivery.

## Out-of-scope

- Constitutional amendments, restoring Docker healthchecks or diagnostic journals, and
  treating cookie authentication alone as route readiness.
- Changes to Tor's Dockerfile, torrc bytes, observer production code, CP authority, socket
  exposure, route admission, fallback behavior or sidecar network privileges.
- T059 orchestration, changes to independent T032/T058/T058a/T161 live-test deadlines,
  and any claim that a 300-second installer budget diagnoses or fixes those live failures.
- General installer redesign, unrelated architecture drift and a whole-stack availability
  guarantee. The existing per-query bound and documented loop overrun remain in force.

The existing installer tests may be extended for the cases above and have their stale
60-second/Docker-health descriptions corrected. Observer test fixtures may model rejected
authentication; existing authentication, finite-output, timeout and isolation assertions
must remain. These are the only authorized changes to pre-existing test expectations.

## Notes

The 2026-09-26 exploration exercised the actual wait function with a simulated clock:
READY at second 90 timed out at 60 with the current default, succeeded at 90 with a
300-second override, and permanently NOT_READY/UNAVAILABLE samples timed out at 300.
Existing focused installer and observer tests passed. This was diagnostic work on unchanged
source, not the ticket's future tests-first record or a new live Tor run.

T161 preserved T160's two cold descriptor-loading failures and later recorded successful
unchanged cold runs. Public-network variability remains explicit. Increasing the installer
budget changes how long the operator waits; it does not make an unready route usable.
