# Prompt 03 — Write CONTRIBUTING.md

Goal: produce `CONTRIBUTING.md` at the repo root. This is the onboarding
document for human contributors and the workflow reference for AI-assisted
contributions.

## Before you start

Read in order:

1. `.specify/memory/constitution.md` — especially the Workflow section and
   Principle VII (test discipline).
2. `CLAUDE.md` — short summary.
3. `specs/000-architecture/spec.md` if it exists (for dev environment details
   — Go version, JDK version, Maven setup). If it doesn't, write generic
   guidance and mark version specifics as `[fill in from architecture spec
   once available]`.

## Deliverable

Create `CONTRIBUTING.md` at the repository root.

### Required sections

1. **Welcome** — short intro: what Stargate is, ethos (privacy-first,
   open-source, honest threat model). Two paragraphs maximum.
2. **License & DCO** — Apache 2.0; contributions accepted with sign-off
   (`git commit -s` adds a `Signed-off-by:` line per the
   Developer Certificate of Origin). No CLA.
3. **Code of Conduct** — adopt Contributor Covenant v2.1; link to
   `CODE_OF_CONDUCT.md` (which can be filed under "TODO: author this file"
   for now).
4. **Reporting security issues** — private channel via GitHub Security
   Advisories (`/security/advisories/new` on the repo). **Do not** open
   public issues for security bugs. Maintainer aims for X-day acknowledgment
   (suggest 7 days as a default; user can revise).
5. **Development environment** — concrete setup steps:
   - Go (pin version from architecture spec)
   - JDK 21+, Maven (pin versions from architecture spec)
   - Docker & Docker Compose
   - Mullvad Browser for testing (LibreWolf optional)
   - Recommended editor configs (gofmt-on-save, EditorConfig file in repo)
   Provide a single `make setup` or `scripts/dev-setup.sh` reference if such
   a script exists in the architecture spec.
6. **Running tests locally** — commands for: Go unit tests, Go contract tests
   per sidecar, Quarkus tests (JVM + native), extension tests if any.
7. **Spec-driven workflow** — the spec-kit flow (`/speckit-specify` →
   `/speckit-clarify` → `/speckit-plan` → `/speckit-tasks` →
   `/speckit-implement`). Explain that **no non-trivial change merges
   without a spec**, that the plan's Constitution Check gate is binding,
   and that bug fixes require a regression test even without a full spec.
8. **AI-assisted workflow** — specifically for contributors using Claude
   Code or other AI coding assistants:
   - The constitution is the authoritative context. Point your assistant
     at it.
   - **Tests first** for privacy-critical paths: ask the assistant to write
     failing tests *from the spec*, then drive implementation to green.
     Do not accept code without tests.
   - AI-generated code carries the same review burden — Principle VIII has
     no AI exception.
   - Suggested model usage: long-context planning with Opus-class; routine
     implementation with Sonnet-class.
9. **PR norms**:
   - One feature/bug per PR; link to the spec.
   - PR title format: `feat(NNN): short description` / `fix: …` /
     `docs: …` (conventional commits flavour, lightweight).
   - Required checks: contract tests pass, `stargate-redteam` review passed
     or findings tracked, no Blocker/Major findings unresolved.
   - Squash-merge default; commit message ends with `Signed-off-by:` line.
   - **No force-pushes to `main`.**
10. **Code style** — language-by-language:
    - Go: `gofmt` + `goimports`; `staticcheck` and `go vet` clean;
      `gosec` for security lints; no `panic` in request path; errors wrapped
      with `%w`.
    - Java/Quarkus: Quarkus formatting via Spotless or similar; standard
      Java naming; no `Object.notify()` / `wait()`; prefer Mutiny `Uni`/`Multi`
      over blocking calls on event-loop threads.
    - Extension JS: TypeScript preferred; ESLint default config; no
      `dangerouslySetInnerHTML`-style escape hatches; no fetch to anything
      not in the user's chosen proxy.
    - Markdown: line length soft 100, hard 120.
11. **Documentation expectations** — when a PR touches behaviour referenced
    in the threat model, the threat model entry updates in the same PR. Same
    for `SECURITY-DECISIONS.md` when a finding is accepted.
12. **Issue triage labels (suggested)** — `priority/blocker|high|medium|low`,
    `area/data-plane|control-plane|extension|infra`, `kind/bug|feature|docs`,
    `security/yes` (private channel only), `needs-spec`, `good-first-issue`.

### Constraints

- **Do not invent commands** that aren't in the architecture spec. If a
  command path is uncertain, write the convention and mark
  `[fill in once architecture spec lands]`.
- **Tone is welcoming but firm on privacy discipline.** Make clear that
  the principles are non-negotiable, but the process is collaborative.

### Definition of done

- File exists at `CONTRIBUTING.md`.
- All 12 sections present (collapse trivial ones if appropriate).
- A first-time contributor can clone the repo, set up the dev environment,
  and submit a small PR following just this file + constitution.
- Suggested `CODE_OF_CONDUCT.md` is flagged as a TODO if not authored
  in this pass.

When done, summarise the file's outline and flag any items you marked
`[fill in once architecture spec lands]` for follow-up.
