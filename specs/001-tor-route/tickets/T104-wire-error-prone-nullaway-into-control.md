---
id: T104
title: 'Wire Error Prone + NullAway into the control-plane Maven reactor'
status: in-review
created: 2026-07-04
last_updated: 2026-09-02
source: hand-authored   # Not in tasks.md; raised after the (1)+(2) tooling
                          # batch landed. See docs/process/workflow.md §"Pure-doc
                          # commits" — this is a code change, so it's a ticket,
                          # not a docs commit.
phase: "0: Bootstrap (tooling)"
story: '-'
blocked_by: [T003]       # T003 created the Maven reactor + parent POM.
parallel: false          # Touches parent POM + every module's POM; serialises.
files_budget: 8
files_scope:
  - control-plane/pom.xml
  - control-plane/api/pom.xml
  - control-plane/core/pom.xml
  - control-plane/persistence/pom.xml
  - control-plane/ui/pom.xml
  - control-plane/runtime/pom.xml
out_of_scope:
  - data-plane/**
  - extension/**
  - proto/**
  - compose/**
  - sidecars/**
  - tests/**
  - scripts/verify.sh    # Mvnw-verify already runs the full build; NullAway
                          # failures fail that gate automatically. No new gate.

# --- Stargate-specific flags ---
privacy_critical: false  # Build tooling, not a privacy surface. The *doctrine*
                          # it enforces ("validate at edges, trust inside",
                          # CONTRIBUTING.md §Working doctrine) IS privacy-
                          # relevant in spirit, but the wiring itself has no
                          # privacy surface. Stargate-redteam N/A.
constitution_refs:
  - "I: Dumb router (the 'no defensive code inside trust boundaries' half —
     NullAway is its positive complement: the contract that makes paranoia
     unnecessary)"
complexity: medium       # Design is settled (infochat D48 is the precedent);
                          # wiring is mechanical. Not `high` — no plan-writer
                          # subagent needed.
risk: low                # Compile-time only; ship behaviour unchanged.
round_cap: 2

spec_refs:
  - CONTRIBUTING.md §"Working doctrine" (the "No defensive code inside trust
    boundaries" rule — this ticket is its mechanical enforcement)
  - CONTRIBUTING.md §"Code style / Java" (the Quarkus formatter / Spotless
    mention — this ticket adds the static-analysis layer alongside)
decision_refs:
  - "infochat decision D48 (docs/process/engineering-rules-verbatim.md §7a —
     the rule text this ticket ports to stargate)"
  - "infochat docs/plan/m1/tickets/M1-164* (the per-module onboarding
     sequence — one subticket per module)"

reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T104: Wire Error Prone + NullAway into the control-plane Maven reactor

## Context

stargate's data plane gets `gofmt + go vet + staticcheck + gosec` (verify.sh
gate 2). The control plane gets **no static-analysis equivalent** — just
`mvn verify`, which is runtime tests only. This ticket closes that gap with
compile-time enforcement of nullness contracts via Error Prone + NullAway.

The doctrine this enforces is already in `CONTRIBUTING.md §"Working doctrine"`:
*"No defensive code inside trust boundaries. Validate at system edges
(external input, config parsing, deserialization, IPC, file I/O); inside
those boundaries, internal-to-internal calls are trusted."* Today that
doctrine has no mechanical enforcement — it relies on the reviewer noticing.
NullAway makes it machine-checked: edge types declare `@Nullable`; internal
types are `@NonNull` by package default; a missing or incorrect contract
fails the build. The reviewer no longer hand-checks annotation presence.

It also feeds the analyze gate (the zecsite "residue" pattern):
nullness-violation properties move from "residue no gate catches" into "gated
by verify.sh fail-closed", shrinking the surface `stargate-redteam` needs to
hunt. Concrete, measurable win for the ticket model.

Precedent: infochat decision **D48** wired the same stack with the same
doctrine. This ticket ports it; the design is settled, not exploratory.

## Analysis

### Must hold

- Every `app.zcat.stargate` package is null-marked (`AnnotatedPackages` config):
  a bare reference type in a parameter / return / field means "never null".
- Genuinely-nullable edge types carry `@Nullable` from
  `org.jspecify.annotations` (JSpecify, NOT JetBrains — see "Gated" below).
- `@NonNull` is never written by hand — non-null is the default.
- A missing or incorrect nullability contract fails `mvn verify` (and therefore
  fails verify.sh gate 3).
- Build behaviour is unchanged for code that compiles today: any currently-
  passing `mvn verify` still passes after wiring (the modules are empty
  skeletons — there is no production Java yet to violate the new policy).

### Gated

- JSpecify is the v1 annotation source, NOT JetBrains `@Nullable`. Reason:
  JSpecify's type-use semantics let `List<@Nullable String>` express "list of
  possibly-null strings", which JetBrains' declaration-only annotations
  cannot. JDK 25 supports JSpecify natively.
- The `-Xplugin:ErrorProne` and `-XepOpt:NullAway:...` flags MUST share a
  single `<arg>` element. Splitting them makes the compiler plugin pass them
  as separate javac arguments and the ErrorProne plugin never sees the
  `-XepOpt` / `-Xep` flags — NullAway silently does not run. Green-but-not-
  enforced. (infochat got bitten by this; do not relearn.)
- `<fork>true</fork>` is required on `maven-compiler-plugin`. Error Prone needs
  deep reflective access into javac internals; `fork` runs javac in a child JVM
  so the `-J--add-exports` / `-J--add-opens` args reach the compiler rather
  than the Maven JVM.
- The Maven BOM-managed-versions invariant (every child POM is version-less)
  is preserved: `jspecify` is declared `provided` in the parent POM's
  `<dependencies>`, child modules pick it up via inheritance, no version
  literal in any child POM.

### Residue

- The `ExcludedFieldAnnotations` list exempts framework-initialized fields
  from NullAway's field-init check: `@Inject` (CDI), `@ConfigProperty`
  (MicroProfile Config) are field-level so the exemption matches directly.
  `@PostConstruct` is a method annotation, so a field initialized inside a
  `@PostConstruct` method is NOT matched by the list — those fields carry
  `@SuppressWarnings("NullAway.Init")` at the declaration instead. This
  suppresses only the init check, keeping the `@NonNull` dereference contract
  intact. *No residue items at wiring time* — the modules are empty; the
  suppressions land incrementally as real code with `@PostConstruct` lands.
- The excluded Error Prone checks (`-Xep:ReferenceEquality:ERROR`,
  `FutureReturnValueIgnored:ERROR`, etc.) are infochat's curated set. stargate
  starts with the same set; if any produces repeated false positives (≥3 per
  the workflow.md deletion-over-addition doctrine) the response is to drop
  that check, not to add `@SuppressWarnings` around it.

## Acceptance

Each item is mechanically checkable — the green build is the proof, not a
reviewer's eye:

1. `control-plane/pom.xml` declares `jspecify` 1.0.0 as a `provided`
   dependency in `<dependencies>` (not `<dependencyManagement>` — children
   inherit it directly).
2. `control-plane/pom.xml` `<pluginManagement>` configures
   `maven-compiler-plugin` with the full annotation-processor + compilerArgs
   block (see §Notes for the verbatim block to port from infochat).
3. `AnnotatedPackages=app.zcat.stargate` (not infochat's `app.zcat.infochat`).
4. Every Error Prone flag and every `-XepOpt:NullAway:...` flag shares ONE
   `<arg>` element (the single-arg rule above). Verified by: `grep -c
   'Xplugin:ErrorProne' control-plane/pom.xml` returns 1.
5. `cd control-plane && ./mvnw -B -q verify` succeeds (modules are empty, so
   NullAway has nothing to flag — the build is green by construction).
6. A deliberate negative check: temporarily add a method
   `String bad(@Nullable String s) { return s.toLowerCase(); }` to any
   module's `src/main/java`, run `./mvnw -B -q verify`, observe the NullAway
   ERROR; revert. (This is a one-shot local falsification, NOT a committed
   test — it proves the wiring actually runs. Without this check the
   single-arg bug from "Gated" can hide silently.)
7. `scripts/verify.sh` gate 3 (`mvnw-verify`) is GREEN at HEAD after wiring.
8. No production Java source carries `@NonNull` (the rule — non-null is the
   default, never written). Verified by:
   `! grep -rn '@NonNull' control-plane/*/src/main/java 2>/dev/null`

## Out-of-scope

- Test-source onboarding. Tests start ungated (the default-testCompile
  execution in each module clears the inherited compilerArgs so EP/NullAway
  does not run on `src/test`). Each module onboards test sources
  independently when it has non-trivial test code that needs the contract —
  separate tickets, mirroring infochat's M1-164a-per-module pattern.
- A JSpecify null-marked-package declaration (`@NullMarked` on a
  `package-info.java`). That's a stricter mode than `AnnotatedPackages` and is
  NOT what infochat does — defer until the package default has proven stable.
- Adding the rule text to `CONTRIBUTING.md §"Code style / Java"`. That's a
  follow-up docs commit once the build is enforcing the contract — a doc
  ahead of the enforcement would be aspirational, not descriptive.

## Notes

### The POM block to port (from infochat decision D48)

The full configuration lives in `infochat/pom.xml` lines 116–191. The two
stargate-specific edits are:

1. `-XepOpt:NullAway:AnnotatedPackages=app.zcat.infochat` →
   `-XepOpt:NullAway:AnnotatedPackages=app.zcat.stargate`
2. The version pins (`error_prone_core` 2.42.0, `nullaway` 0.10.25,
   `jspecify` 1.0.0, `maven-compiler-plugin` 3.13.0) are infochat's at the
   time of D48. Verify each is still current at wiring time (run
   `./mvnw versions:display-dependency-updates` in the control-plane reactor
   and bump any that have moved); pin to a specific version, do not use
   `RELEASE` or `LATEST`.

The JDK 25 `--add-exports` / `--add-opens` block (10 lines) is verbatim —
those are javac internals Error Prone needs reflectively and the set is
stable across JDK versions infochat has tested through 25.

### Per-module onboarding (light)

Because the config lives in parent `<pluginManagement>`, **main sources are
gated automatically** in every reactor module — no per-module activation
stanza needed for `src/main`. Each module adds ONLY the test-source
exemption:

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-compiler-plugin</artifactId>
  <executions>
    <execution>
      <id>default-testCompile</id>
      <configuration>
        <compilerArgs combine.self="override"/>
      </configuration>
    </execution>
  </executions>
</plugin>
```

This stanza exists ONLY to carry the test-source exclusion; the inherited
config handles main sources. Matches infochat's M1-164b..f pattern.

### Why JSpecify over JSR-305 / JetBrains

JSR-305 is dormant; JetBrains annotations are declaration-only (can't express
`List<@Nullable String>`). JSpecify 1.0.0 ships type-use semantics, is
actively maintained, and integrates with NullAway via `AnnotatedPackages`.
The dependency is `provided` scope — never on the runtime classpath, build-
time only.

### Related tickets to file after this one lands

- T104a (per-module test-source onboarding — one subticket per stargate
  module when it acquires non-trivial test code; mirror infochat M1-164a).
- T104b (CONTRIBUTING.md §"Code style / Java" update — adds the
  nullness-contract rule, mirroring infochat `engineering-rules-verbatim.md
  §7a`).
- Optional T104c (a `package-info.java` with `@NullMarked` once the package
  default has proven stable for ≥1 feature).
