---
id: T113
title: 'Drop the inert PostConstruct token from ExcludedFieldAnnotations'
status: pending
created: 2026-09-02
last_updated: 2026-09-02
source: T104 review round 1 (APPROVE-WITH-FIXES) RECOMMENDED-FOLLOW-UP #1
        — code change, hence outside that round's comment-only FIX ITEMS
phase: "0: Bootstrap (tooling)"
story: '-'
blocked_by: []
parallel: true
files_budget: 2
files_scope:
  - control-plane/pom.xml
out_of_scope:
  - control-plane/*/pom.xml   # Module POMs: the flag is inherited, not overridden.
  - control-plane/*/src/**
  - scripts/verify.sh

privacy_critical: false
constitution_refs: []       # Build tooling; no principle surface.
complexity: low
risk: low
round_cap: 2

spec_refs:
  - "T104 §Residue (ExcludedFieldAnnotations = @Inject + @ConfigProperty;
    @PostConstruct is a method annotation, NOT matched — suppressions carry
    the contract instead)"
decision_refs:
  - "target/runs/T104.verdict (archived in T104's review record) — finding 1"

reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T113: Drop the inert PostConstruct token from ExcludedFieldAnnotations

## Context

T104's flag list carries `jakarta.annotation.PostConstruct` in
`-XepOpt:NullAway:ExcludedFieldAnnotations` (ported verbatim from infochat
D48). The token is provably inert: NullAway matches the list against
annotations *on fields*, and `@PostConstruct` is a method-level annotation
javac will never accept on a field — so it can never match. T104's §Residue
specifies the list as `@Inject` + `@ConfigProperty` only, precisely because
@PostConstruct-initialized fields are NOT exempted and carry
`@SuppressWarnings("NullAway.Init")` instead.

T104's round-1 review flagged the self-contradiction (flag list includes
the token; T104's own comment 8 lines up says it never matches) and applied
the comment-only half of the fix ("deliberately inert" clause) under
APPROVE-WITH-FIXES. This ticket lands the code half: remove the token so
the flag matches §Residue verbatim and the clarifying comment clause goes
away with it. Behaviour is identical either way — this is a
contradiction-removal change, so a future reader of the wiring cannot
misread the exemption list as covering @PostConstruct-init fields.

(Nota: T104c was reserved in T104 §Notes for an optional `@NullMarked`
package-info ticket whose gate — "package default proven stable for ≥1
feature" — is unmet; it is deliberately not filed, so the T104x letter
sequence stops at T104b and this follow-up takes the next plain number.)

## Analysis

### Must hold

- The single `<arg>` element loses exactly one token:
  `-XepOpt:NullAway:ExcludedFieldAnnotations=jakarta.inject.Inject,org.eclipse.microprofile.config.inject.ConfigProperty`
  (order: the remaining two keep their relative order).
- The `-Xplugin:ErrorProne ...` single-arg rule (T104 §Gated) is untouched —
  the edit stays inside the existing one `<arg>`.
- The comment's "deliberately inert" clause (added by T104's AWF fix) is
  removed together with the token — after this ticket, the comment and the
  flag agree with each other AND with T104 §Residue.
- All other flags, versions, and the fork/processor config are byte-identical.

### Residue

- None expected. If a future Quarkus extension ever introduces a
  field-level `@PostConstruct`-style annotation, that is a new decision
  with its own evidence — not this token.

## Acceptance

1. `grep -o 'ExcludedFieldAnnotations=[^ ]*' control-plane/pom.xml` returns
   `jakarta.inject.Inject,org.eclipse.microprofile.config.inject.ConfigProperty`
   (no `jakarta.annotation.PostConstruct`).
2. `grep -c 'Xplugin:ErrorProne' control-plane/pom.xml` still returns 1
   (single-arg rule intact).
3. `grep -c 'deliberately inert' control-plane/pom.xml` returns 0 (the
   now-moot clause is gone).
4. `cd control-plane && ./mvnw -B -q verify` GREEN (behaviour identical —
   the token could never match).
5. `scripts/verify.sh` GREEN at HEAD.

## Out-of-scope

- Any other flag, version, or comment in the compiler block.
- Test-source onboarding (T104a) and the CONTRIBUTING.md rule text (T104b).
