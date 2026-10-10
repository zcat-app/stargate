# Contributing to Stargate

## Welcome

Stargate is an open-source, multi-protocol privacy-routing proxy. A browser
extension picks the route per request (Tor, I2P, Nym mixnet, Direct); the
proxy forwards bytes to the appropriate sidecar. It is designed to be
family-shareable, Docker-deployed, and honest about what it does and does
not protect against.

We welcome contributions — code, specs, threat-model entries, documentation,
review. Privacy discipline is non-negotiable: the principles in
`.specify/memory/constitution.md` are binding, not aspirational. The process
of getting work merged, on the other hand, is meant to be collaborative and
unintimidating. This document explains how those two things fit together.

## Current constitutional boundaries

Constitution T156 (2026-09-12) is authoritative. Proxy negotiation/IPC authentication does not
permit inspection of tunneled application bytes. DP/CP network privileges follow its actor
matrix; sidecar maintenance is not unrestricted proxy egress. Logs and exported metrics contain
only completed immutable hourly aggregates, including operational diagnostics. Protected-route
failure must not fall back to Direct. Current implementation gaps are tracked in feature 001's
foundation contract and ticket plan, not grandfathered by old accepted decisions.

Privacy-critical infrastructure follows the strictest tests-first category. Review evidence
identifies the exact candidate, actual reviewer capability and executed/skipped checks. Follow
`docs/process/workflow.md` for combined regression/fix tickets; no red-only dependency deadlock.
Constitution amendments follow its active pre-release/post-release Governance section. Risk
acceptance never waives an invariant, and user-authorized reconciliation may repair source drift
without claiming that the existing implementation already conforms.

## License & Developer Certificate of Origin

Stargate is licensed under **Apache License 2.0** (see `LICENSE`). New
source files carry the standard Apache 2.0 header.

There is **no CLA**. Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).
Sign off on every commit:

```bash
git commit -s -m "feat(007): add stream-isolation contract test"
```

`-s` appends a `Signed-off-by: Your Name <your@email>` line to the commit
message. By doing so you certify the DCO terms — namely that you have the
right to submit the contribution under the project's license. Commits
without a sign-off will be asked to amend or rebase before merge.

## Code of Conduct

This project follows the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
See `CODE_OF_CONDUCT.md` for the adopted text and the private reporting
channel.

In short: be kind, assume good faith, accept review, give review with the
same respect you want to receive. Privacy work attracts strong opinions —
disagree about the technical substance, not the people holding it.

## Reporting security issues

**Do not open a public GitHub issue for security bugs.**

Report privately via GitHub Security Advisories:

> `https://github.com/zcat-app/stargate/security/advisories/new`

The maintainer aims to acknowledge new advisories within **7 days**. A fix
timeline is agreed per finding. If you have not received an acknowledgement
within that window, ping the maintainer through any public channel
*without* disclosing the bug — for example, "I filed a security advisory
on YYYY-MM-DD and would appreciate a status update."

Coordinated disclosure is the default. Once a fix is released, the
advisory is published with credit to the reporter (unless they ask
otherwise). If you discover that a privacy property documented in
`THREAT-MODEL.md` does not hold, that is a security issue — please report
it through the same channel.

## Development environment

### Prerequisites

- **Go 1.26.3** — pinned in `data-plane/go.mod` via the `toolchain`
  directive.
- **JDK 25 LTS** — pinned in `control-plane/pom.xml` via
  `<maven.compiler.release>25`. Any JDK 25 distribution (Temurin,
  Liberica, Zulu, Corretto) works for local development; the release
  artefact pins one specific distribution for byte-reproducible builds.
- **Quarkus 3.40 LTS** — pinned in `control-plane/pom.xml` via the
  `<quarkus.platform.version>` property and managed by the Quarkus
  platform BOM. Do not bump this casually; LTS-to-LTS upgrades follow
  the same documented process as sidecar image bumps (constitution
  Principle IV).
- **Maven 3.9.14** — use the checked-in `control-plane/mvnw` wrapper.
- **Docker** and **Docker Compose v2** — required for any integration or
  end-to-end work. The compose stack lives under `compose/`.
- **Mullvad Browser** — the first-class target browser. Install from
  <https://mullvad.net/en/download/browser>. **LibreWolf** is the
  tested-secondary target. Chromium-family browsers are explicitly
  unsupported (constitution: Tech Stack).
- **GraalVM / Mandrel** — required only for building Quarkus native-image
  artefacts. **Mandrel 25** (the JDK 25 native-image builder) is pinned by
  digest in the parent POM; for local native builds, match that digest.
  The concrete builder digest remains a release prerequisite tracked by
  architecture §15 open question 9; native-image work is not part of feature
  001.

### One-shot setup

A bootstrap script is planned at `scripts/dev-setup.sh` (or `make setup`)
that verifies tool versions and warms the build caches. Until it exists, use
the manual sequence:

```bash
# 1. clone
git clone https://github.com/zcat-app/stargate.git
cd stargate

# 2. data plane
cd data-plane && go mod download && go build ./... && cd ..

# 3. control plane
cd control-plane && ./mvnw -B verify -DskipTests && cd ..

# 4. bring up a local stack for manual smoke testing
./scripts/stargate init --profile local
```

The `scripts/stargate` entry-point is described in
`specs/000-architecture/spec.md` §9; subcommands are
`init | enroll | export | import | wipe | status | update`.

### Editor configuration

- An `.editorconfig` file ships at the repo root and is honoured by most
  editors out of the box.
- **Go**: enable `gofmt`/`goimports` on save. `staticcheck` and
  `golangci-lint` as your linter front-end.
- **Java**: use the Quarkus formatter configuration (Spotless or
  equivalent) — `./mvnw spotless:apply` if configured. IntelliJ users can
  import the project's code style from `control-plane/.idea/` if provided.
- **JavaScript/TypeScript** (extension): ESLint with the repo's
  `extension/.eslintrc` config. Prettier on save.
- **Markdown**: soft-wrap at 100 columns, hard-wrap at 120. Most editors
  with the `.editorconfig` plugin handle this.

## Running tests locally

Tests are layered. Run the layer that matches the area you touched. The
single green gate that runs every layer is `scripts/verify.sh` (see
§Verification below); the per-area commands here are for the fast inner
loop.

### Go workspace — unit + contract tests (every module)

`scripts/verify.sh`'s `go-workspace` gate discovers every workspace Go
module from `go.work` (data plane, proto, contract, integration, shared log
invariants) and runs it with JSON skip accounting: a package whose tests
all skip is reported SKIP, never PASS. Docker/live/release-backed suites
carry `//go:build docker|live|release` and are accounted SKIP[<cadence>] in
the hermetic PR run (compile-checked via `go vet -tags`); the named job
opts them back in with the SAME entrypoint:

```bash
# Hermetic PR gate (default): every module, docker/live/release excluded.
bash scripts/verify.sh

# Named Docker job: same script, opts docker suites INTO execution.
STARGATE_TEST_TAGS=docker bash scripts/verify.sh

# A single module's inner loop:
cd tests/contract && go test ./...
cd data-plane        && go test ./...
```

### Quarkus control plane

```bash
cd control-plane

# JVM tests (fast loop):
./mvnw -B test

# Including @QuarkusIntegrationTest against a packaged JAR:
./mvnw -B verify

# Native-image tests (slow; the native build itself takes minutes):
./mvnw -B verify -Pnative
```

### Browser extension

```bash
cd extension
# Once T034b lands:
./run-tests.sh
```

Feature 001 uses Node 20 LTS's built-in `node:test` runner and no npm
dependencies. Until T034b creates `run-tests.sh`, only the packaging check is
available.

### Reproducibility tests

```bash
go test ./tests/reproducibility/...
```

These build the data-plane binary, the control-plane JAR, and the
extension zip twice in clean containers and `cmp` the outputs. They must
pass on every release tag.

## Spec-driven workflow

**No non-trivial change merges without a spec.** Bug fixes do not require
a full spec but **require a regression test** that fails before the fix
and passes after.

The flow uses spec-kit slash commands inside an AI-assisted editor (or the
equivalent manual sequence — these are just templates and conventions):

1. `/speckit-specify` — produces `specs/NNN-feature/spec.md`.
2. `/speckit-clarify` — optional, surfaces ambiguities before planning.
3. `/speckit-plan` — produces `specs/NNN-feature/plan.md`. The plan
   **must include an explicit Constitution Check** verifying that no
   principle is violated. A plan that cannot pass Constitution Check is
   either revised or escalated to a constitution amendment — never silently
   merged.
4. `/speckit-tasks` — produces an actionable, dependency-ordered task list.
5. `/speckit-implement` — drives implementation against the tasks.

The Constitution Check gate is **binding**. If a reviewer flags a
principle violation that the plan glossed over, the PR is held until the
plan is revised or the constitution is amended through the documented
governance process (see `.specify/memory/constitution.md` § Governance).

> **What counts as "non-trivial"?** A typo fix, a dependency-version bump
> covered by automation, a doc-only correction, or a comment polish does
> not need a spec. Anything that changes behaviour, adds a code path,
> alters a public contract, or touches a privacy-critical surface (DNS,
> routing, headers, auth, sidecar contracts) does.

## AI-assisted workflow

This project is developed in collaboration with AI coding assistants —
Claude Code, in particular. The conventions below apply whether you are
the human pair or the AI agent is doing the typing.

- **The constitution is the authoritative context.** Point your assistant
  at `.specify/memory/constitution.md` before any non-trivial task. The
  `CLAUDE.md` file at the repo root is a short hand-off; the constitution
  is the source of truth.
- **Tests first for privacy-critical paths.** Ask the assistant to write
  failing tests derived from the spec (`specs/NNN-feature/spec.md`)
  *before* it writes implementation. Then drive the implementation to
  green. Do not accept code without tests. This is Constitution
  Principle VII; it has no AI exception.
- **AI-generated code carries the same review burden.** Per-ticket review runs
  through `scripts/review-task.sh`: one GLM and one Codex reviewer, each
  covering correctness and adversarial security in the same single-gate pass.
  A cumulative redteam pass is also required on every feature spec and
  release, regardless of who authored the code. Principle VIII has no AI
  exception either.
- **Suggested model usage.** Long-context planning, spec authoring, threat
  modelling, and adversarial review benefit from an Opus-class model.
  The main thread orchestrates ticket implementation, dispatching one fresh
  developer subagent per ticket with the same harness, model and reasoning
  settings. The developer has its own context and reports to the orchestrator;
  both retain their journal and handoff duties.
- **Do not paste secrets into prompts.** No bearer tokens, no admin
  enrollment codes, no private keys, no production database dumps.
- **Cite the principle when constraining the assistant.** "Principle I
  says the data plane must not parse payloads — rewrite without the
  header inspection" is a precise instruction; "make it more private" is
  not.

### Working doctrine

Adopted from an external team's hard-won AI-assisted workflow. These apply to
every change, large or small — they are what keep autonomous runs honest.

- **Falsify before publishing.** Every claim, recommendation, or change is a
  hypothesis. Before stating it, name what would make it *false* and check
  *that* — re-checking the supporting evidence you already have is confirmation,
  not verification. Also ask "is there a better option I haven't considered?"
  If either step fails, revise or drop it. A five-line suggestion gets this too.
- **Surgical changes only.** Every changed line traces to an acceptance
  criterion, the explicit request, or an orphan your own change created. No
  drive-by edits to adjacent code, comments, or formatting. Spotted a real bug
  or a better approach mid-task? File a follow-up task — don't expand scope.
- **Ground before acting.** Read the whole task and verify the relevant state
  on disk *before* batching edits or running a build that depends on it. Don't
  pair a read with the action that consumes it in the same blind step.
- **No defensive code inside trust boundaries.** Validate at system *edges*
  (external input, config parsing, deserialization, IPC, file I/O — e.g. the
  bind-safety check, token auth, proto decode). *Inside* those boundaries,
  internal-code-calling-internal-code is trusted: no null checks for values that
  can't be null, no try/catch around things that can't throw. Make the contract
  explicit (typed nullability, schema) so the paranoia is unnecessary, and let
  the build enforce it. This is Principle I's "dumb router" generalised to a
  coding standard for both planes. On the control plane the enforcement is
  mechanical: Error Prone + NullAway gate the nullness contract at compile
  time (§"Code style / Java" — Nullness contract).

The per-task review loop these feed into—the isolated one GLM/one Codex
`stargate-review` single gate launched only by `scripts/review-task.sh`, the
round cap, and the escalation menu—is documented at
`.specify/memory/review-loop.md`. The single green gate every "done" depends on
is `scripts/verify.sh`.

### Updating executable CI inputs

Constitution IV/VI requires a reviewed, immutable identity for every Action
and agent CLI that runs in CI. External `uses:` references in
`.github/workflows/` and `.github/actions/` use full 40-character commits;
repository-local `./.github/actions/` references resolve from the checked-out
source. The `agent-task` job downloads exact CLI release archives and checks
their recorded SHA-256/SHA-512 digests before unpacking them.

To promote an update, open a PR that records the upstream release/version and
commit or archive digest from the publisher's GitHub release/tag or npm registry
metadata. For an annotated Git tag, dereference it to the commit with
`git rev-parse <ref>^{commit}` or the publisher's `/commits/<ref>` API; the
plain `git ls-remote refs/tags/<ref>` value can be a tag-object hash and is not
the executable commit. Review the upstream changelog and executable diff,
then update the commit or version URL **and** its digest together. Fetch the archive yourself
and verify it against that metadata; a checksum copied into a comment is not
verification. Run `bash tests/contract/workflow/ci_inputs_test.sh` and
`bash scripts/verify.sh`, then obtain the normal ticket review. The PR must
identify what was executed and which checks ran or skipped. No tracker or
workflow promotes these pins automatically, and deployed updates remain an
explicit operator action.

## PR norms

- **One feature or bug per PR.** Link to the feature spec
  (`specs/NNN-feature/spec.md`) in the PR description, or to the issue
  for bug-only fixes.
- **PR title format** (conventional-commits flavour, lightweight):
  - `feat(NNN): short description` — new behaviour from feature spec NNN
  - `fix: short description` — bug fix (link the regression test)
  - `docs: short description` — docs only
  - `chore: short description` — tooling, deps, repo hygiene
  - `test: short description` — tests only
  - `refactor: short description` — no behaviour change
- **Required checks before merge**:
  - All relevant contract tests pass.
  - The ticket's single-gate reviewer set passed clean or its Blocker/Major
    findings are resolved or accepted (with a rationale entry in
    `SECURITY-DECISIONS.md`); milestone redteam has swept the cumulative
    diff where the milestone requires it.
  - Reproducibility tests pass (where touched).
  - Plan's Constitution Check section is filled in and accurate.
- **Squash-merge** is the default. The squashed commit message ends with
  the `Signed-off-by:` line from the original commits, plus
  `Co-authored-by:` lines for everyone who contributed.
- **No force-pushes to `main`.** Force-push inside an open PR branch is
  fine until review starts; once a reviewer is reading, prefer additional
  commits and let the squash-merge fold them.
- **Rebase before merge** to keep `main` linear, or use the GitHub
  "Squash and merge" button — either is acceptable.

## Code style

### Go (data plane)

- `gofmt` + `goimports` clean. CI fails on unformatted code.
- `go vet ./...` clean.
- `staticcheck ./...` clean.
- `gosec ./...` reviewed; non-trivial findings get a comment with
  rationale or an inline `//nolint:gosec // reason: ...`.
- **Never `panic` in the request path.** Errors are values; wrap with
  `fmt.Errorf("forwarding to %s: %w", route, err)` so `errors.Is` /
  `errors.As` keep working.
- No `init()` functions for anything beyond `flag` or driver
  registration — they are invisible at call sites.
- Goroutines have a documented exit condition. No "fire and forget" in
  the data plane.

### Java / Quarkus (control plane)

- **Nullness contract (build-enforced since T104).** Every
  `app.zcat.stargate` package is @NonNull-by-default (NullAway
  `AnnotatedPackages`): a bare reference type means "never null". A
  genuinely-nullable parameter, return, or field carries `@Nullable` from
  `org.jspecify.annotations` (JSpecify — type-use semantics, e.g.
  `List<@Nullable String>`; never JetBrains or JSR-305). **Never write
  `@NonNull` by hand** — non-null is the default. A missing or incorrect
  contract fails `./mvnw verify` (Error Prone + NullAway). Exceptions, not
  norms: `@SuppressWarnings("NullAway.Init")` on fields initialized in
  `@PostConstruct` methods (suppresses only the init check); if a check
  produces ≥3 false positives, drop the check rather than suppress around
  it (workflow.md deletion-over-addition).
- Formatter: Spotless (or the Quarkus-default formatter) applied via
  `./mvnw spotless:apply`.
- Standard Java naming (`UpperCamelCase` types, `lowerCamelCase` methods).
- **Never use `Object.notify()` / `wait()` / `notifyAll()`.** Use
  `java.util.concurrent` primitives or, preferably, Mutiny `Uni`/`Multi`.
- **Never call blocking code on the Quarkus event-loop thread.** Use
  `@Blocking`, or shift to a worker pool with
  `uni.runSubscriptionOn(executor)`. The `stargate-perf` agent will
  flag blocking-on-event-loop as a Major finding.
- Persistence uses Hibernate Panache; migrations go through Flyway. Do
  not write raw `Statement` SQL outside migration scripts.
- Operational events contribute only to completed-hour aggregates (Principle III).
  Runtime diagnostic stdout/stderr, framework logging and crash dumps are suppressed;
  debug mode cannot enable a persistent administrative or request journal.

### Browser extension (JavaScript / TypeScript)

- **Feature 001 stays vanilla JavaScript (ES2022)** with no build step or npm
  runtime dependencies. TypeScript requires a later spec that defines and
  pins the compiler/reproducibility surface.
- ESLint default config plus the repo's `extension/.eslintrc` overrides.
- **No `innerHTML` or `dangerouslySetInnerHTML`-style sinks.** Build DOM
  with `document.createElement` / `textContent`.
- **No `fetch` (or `XMLHttpRequest`) to anything outside the user's
  configured proxy.** No telemetry. No update-check pings. No "phone
  home". Principle III is enforced here in code, not policy.
- The blocklist is shipped in-package; never fetched at runtime.

### Markdown

- Soft wrap at 100 columns, hard wrap at 120.
- Use ATX headings (`#`, `##`, `###`).
- Reference links over inline links when the same URL appears multiple
  times.
- Code blocks have a language tag (` ```go `, ` ```bash `, ` ```sql `).

## Documentation expectations

Some changes pull adjacent docs along with them. A PR is not done until
those edits land too:

- **Threat model.** If a PR changes behaviour referenced in
  `THREAT-MODEL.md` (per-route protections, per-mode bind safety, leak
  surface, trusted parties), the threat-model entry updates **in the
  same PR**. A doc-lag PR is rejected.
- **Security decisions.** If `stargate-redteam` raises a Blocker or
  Major finding that the PR accepts rather than fixes, the rationale is
  appended to `SECURITY-DECISIONS.md` (append-only) in the same PR.
- **Build diffs.** If a change is expected to alter the reproducibility
  diff surface (new build flag, new bundled asset, native-image
  reachability config), document the expected variation in
  `BUILD-DIFFS.md`.
- **Architecture.** If a PR shifts module boundaries, port assignments,
  or the inter-plane contract, update `specs/000-architecture/spec.md`
  and `ARCHITECTURE.md` accordingly.
- **Constitution.** If a PR cannot pass Constitution Check without
  amending a principle, the constitution amendment goes through the
  governance flow (`.specify/memory/constitution.md` § Governance) —
  not bundled with the code change.

## Issue triage labels (suggested)

Maintainer applies on triage; contributors can suggest in the PR body.

- **Priority**: `priority/blocker`, `priority/high`, `priority/medium`,
  `priority/low`.
- **Area**: `area/data-plane`, `area/control-plane`, `area/extension`,
  `area/infra`, `area/docs`.
- **Kind**: `kind/bug`, `kind/feature`, `kind/docs`, `kind/test`,
  `kind/refactor`, `kind/chore`.
- **Security**: `security/yes` — flags an issue that should have been
  filed privately. Public-issue triage will move these to a private
  advisory and close the public copy.
- **Process**:
  - `needs-spec` — issue is actionable but blocked on a spec.
  - `needs-clarify` — spec exists but has open `NEEDS CLARIFICATION`
    markers.
  - `good-first-issue` — well-scoped, documented, with a clear
    completion criterion. Ideal for new contributors.
  - `help-wanted` — maintainer welcomes contributions; not necessarily
    beginner-friendly.

---

If something in this document is wrong, unclear, or out of date, that
itself is a `docs:` PR worth opening. Thanks for contributing.
