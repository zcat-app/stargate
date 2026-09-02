---
id: T104b
title: 'Add the nullness-contract rule to CONTRIBUTING.md code style'
status: pending
created: 2026-09-02
last_updated: 2026-09-02
source: T104 §Notes "Related tickets to file after this one lands" — the
        docs follow-up, deliberately filed AFTER the enforcement (T104)
        landed so the text is descriptive, not aspirational
phase: "0: Bootstrap (tooling)"
story: '-'
blocked_by: [T104]
parallel: true
files_budget: 2
files_scope:
  - CONTRIBUTING.md
out_of_scope:
  - control-plane/**       # Enforcement already landed via T104; no build change here.
  - docs/process/engineering-rules-verbatim.md  # infochat-side doc; do not create a mirror file.

privacy_critical: false
constitution_refs:
  - "I: Dumb router (the no-defensive-code-inside-trust-boundaries half —
     the rule text documents its mechanical enforcement)"
complexity: low
risk: low
round_cap: 2

spec_refs:
  - CONTRIBUTING.md §"Working doctrine" ("No defensive code inside trust
    boundaries")
  - CONTRIBUTING.md §"Code style / Java"
decision_refs:
  - "infochat decision D48 (docs/process/engineering-rules-verbatim.md §7a —
     the rule text this ticket ports to stargate)"

reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T104b: Add the nullness-contract rule to CONTRIBUTING.md code style

## Context

T104 made the nullness contract machine-checked: `app.zcat.stargate` is
@NonNull-by-default (NullAway `AnnotatedPackages`), genuinely-nullable edge
types carry JSpecify `@Nullable`, and a missing or incorrect contract fails
`mvn verify`. CONTRIBUTING.md does not yet describe any of this — §"Code
style / Java" has no nullness rule, and §"Working doctrine"'s
"no defensive code inside trust boundaries" still says "let the build
enforce it" without saying the build now does.

T104's §Out-of-scope explicitly deferred this text until enforcement
existed: a doc ahead of the enforcement would be aspirational, not
descriptive. Enforcement is now real (T104 review round 1 verified the
wiring end-to-end, including the negative falsification), so the rule text
lands here as documentation of what the build already does.

## Analysis

### Must hold

- The rule text mirrors infochat `engineering-rules-verbatim.md` §7a (D48)
  adapted to stargate: non-null is the package default; `@Nullable`
  (JSpecify, never JetBrains/JSR-305) marks genuinely-nullable parameters,
  returns, and fields; `@NonNull` is never written by hand; violations fail
  `mvn verify` (Error Prone + NullAway, wired in T104).
- The §"Working doctrine" bullet gains a pointer to the mechanical
  enforcement, not a rewrite — surgical edit.
- The text documents the escape hatches as exceptions, not norms:
  `@SuppressWarnings("NullAway.Init")` for `@PostConstruct`-initialized
  fields (T104 §Residue), and the deletion-over-addition response to
  repeated false-positive checks (≥3 → drop the check, per workflow.md).

### Residue

- None. Pure-doc change; no code path exists to describe incorrectly.

## Acceptance

1. CONTRIBUTING.md §"Code style / Java" states the nullness contract rule
   (default non-null, JSpecify `@Nullable`, no hand-written `@NonNull`,
   build-enforced via Error Prone + NullAway since T104).
2. The §"Working doctrine" "No defensive code inside trust boundaries"
   bullet references the enforcement (one-line edit; the bullet's meaning
   is unchanged).
3. No other CONTRIBUTING.md sections change. `git diff --stat` shows
   CONTRIBUTING.md only.
4. Claim-check: every factual statement in the new text is true of the
   build at HEAD (verify each against control-plane/pom.xml — flag names,
   package default, scope of the gate — not against T104's ticket prose).

## Out-of-scope

- Any POM or source change (T113 owns the ExcludedFieldAnnotations token
  cleanup; T104a owns test-source onboarding).
- Creating a stargate copy of infochat's engineering-rules-verbatim.md.
