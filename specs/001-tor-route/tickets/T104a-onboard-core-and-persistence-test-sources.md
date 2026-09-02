---
id: T104a
title: 'Onboard core and persistence test sources to NullAway'
status: done
created: 2026-09-02
last_updated: 2026-09-02
source: T104 §Notes "Related tickets to file after this one lands" (the
        M1-164a-per-module pattern; filed at T104 landing because core and
        persistence already carry non-trivial test classes)
phase: "0: Bootstrap (tooling)"
story: '-'
blocked_by: [T104]
parallel: false         # Both modules' POMs; same files T104 touched.
files_budget: 8
files_scope:
  - control-plane/core/pom.xml
  - control-plane/persistence/pom.xml
  - control-plane/core/src/test/**
  - control-plane/persistence/src/test/**
out_of_scope:
  - control-plane/pom.xml           # Parent wiring is T104's; done.
  - control-plane/api/**
  - control-plane/ui/**
  - control-plane/runtime/**
  - control-plane/*/src/main/**     # Main sources are gated since T104.
  - scripts/verify.sh

privacy_critical: false  # Gating config + annotation contracts on test code;
                          # the tests themselves do not change behaviour.
constitution_refs:
  - "VII: Tests-first for privacy-critical paths (the contract this extends
     to test sources so test/production nullness semantics cannot drift)"
complexity: medium
risk: low
round_cap: 2

spec_refs:
  - "T104 §Out-of-scope (tests start ungated; each module onboards when it
    has non-trivial test code) and §Notes per-module stanza"
decision_refs:
  - "infochat docs/plan/m1/tickets/M1-164* (per-module test-source
     onboarding sequence)"

reviews: { round: 1, date: 2026-09-02, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T104a: Onboard core and persistence test sources to NullAway

## Context

T104 wired Error Prone + NullAway over `src/main` in every reactor module;
each module's POM carries a `default-testCompile` stanza that clears the
inherited `compilerArgs` so `src/test` stays ungated. Two modules have
already acquired non-trivial test code at T104 landing:

- `core`: `Argon2idParamsTest`, `TokenLifecycleContractTest` (auth contract
  surface — the nullness semantics these tests assume should be the same
  machine-checked contract main code runs under).
- `persistence`: `V001MigrationTest`, `V001SchemaContractTest`,
  `RepositoryShapeContractTest`, `AuditLogAppendOnlyTest`.

Leaving test sources permanently ungated means a test can silently encode
nullness semantics (a null-tolerant helper, an accidental @Nullable-looking
contract) that the production gate would reject — test/production drift
invisible to both the reviewer and the build. This ticket closes that for
the two modules that have tests today, mirroring infochat's M1-164
per-module onboarding. api / ui / runtime onboard via future micro-tickets
if and when they acquire non-trivial test code.

## Analysis

### Must hold

- Removing a module's `default-testCompile` override stanza (or emptying its
  purpose) makes `src/test` inherit the parent's EP + NullAway config —
  same single-arg flag delivery, `AnnotatedPackages=app.zcat.stargate`.
- Test classes live in `app.zcat.stargate.*`, so NullAway's
  @NonNull-by-default applies to them exactly as to main sources.
- Any violations the gate surfaces are fixed by making the contract
  explicit (`@Nullable` where genuinely nullable) — never by widening
  suppression beyond `@SuppressWarnings("NullAway.Init")` for
  framework-initialized fields per T104 §Residue, and never by dropping
  checks.
- The module POMs stay version-less (BOM-managed-versions invariant).

### Gated

- ExcludedFieldAnnotations (`@Inject`, `@ConfigProperty`) covers CDI field
  init in tests the same as main. `@PostConstruct`-initialized fields still
  need `@SuppressWarnings("NullAway.Init")` (T104 §Residue).
- Quarkus `@BeforeEach`/lifecycle methods get no special treatment; a
  genuinely-nullable test helper parameter carries `@Nullable` (JSpecify).

### Residue

- If a test framework requires a pattern NullAway cannot express (e.g.
  JUnit extension field injection not covered by ExcludedFieldAnnotations),
  the per-declaration `@SuppressWarnings` is the escape — each use is a
  residue item listed in this ticket's body, not a silent norm.

## Acceptance

1. `core/pom.xml` and `persistence/pom.xml` no longer carry the
   `default-testCompile` override stanza (or carry an explicit re-enable
   that provably inherits the parent compilerArgs — effective POM shows the
   testCompile execution with the same arg count as default-compile).
2. `cd control-plane && ./mvnw -B -q verify` GREEN with NullAway active on
   both modules' test sources. Evidence the gate actually runs on tests:
   the one-shot negative probe — temporarily add a null-unsafe helper to
   any `src/test` class, observe the `[NullAway]` ERROR, revert (same
   falsification discipline as T104 AC #6).
3. Every test-source change is an explicit nullness contract (JSpecify
   `@Nullable`); zero `@SuppressWarnings` beyond the `NullAway.Init`
   pattern; zero `@NonNull` written by hand.
4. `scripts/verify.sh` GREEN at HEAD.
5. api / ui / runtime POMs unchanged (still carry the exemption stanza).

## Out-of-scope

- api / ui / runtime test onboarding (no test code exists there).
- Main-source changes of any kind.
- The CONTRIBUTING.md rule text (T104b) and the ExcludedFieldAnnotations
  token cleanup (T113).
