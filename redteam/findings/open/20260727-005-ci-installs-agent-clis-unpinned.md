---
id: 20260727-005-ci-installs-agent-clis-unpinned
status: open
severity: major
principle: [IV]
threat-model: n/a — CI/supply-chain surface; THREAT-MODEL has no CI section (see 20260727-004)
location: .github/workflows/agent-task.yml:126,132
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: null
---

# CI installs agent CLIs via unpinned `curl | bash` and floating `npm -g`

## What the code does

```yaml
curl -fsSL https://opencode.ai/install | bash          # :126
npm install -g @anthropic-ai/claude-code               # :132
```

The `run` job holds `ANTHROPIC_API_KEY` (`:112`) and — before the 20260727-004 fix, at
workflow scope; after it, at job scope — a repo-write `GITHUB_TOKEN`. It fetches an
installer over the network with no version and no digest, pipes it to a shell, and
separately installs an npm package at floating latest. The workflow's own comment at
`:123-124` admits: *"Pin to a version once stargate standardizes; for experimentation,
latest is fine."*

## Why it leaks

Constitution Principle IV: *"All external components are referenced by image digest… Update
mechanisms are themselves remote-code-execution channels; making them deliberate and
auditable is non-negotiable."* A `curl | bash` at floating latest is the exact prohibited
shape.

A compromise of `opencode.ai/install`, of the npm package, or a MITM/DNS hijack of the fetch
injects arbitrary code into a job holding a live provider API key and a repo-write token —
silent TCB substitution with no audit anchor. Note this is a *different* channel from
20260727-004: fixing the comment-body injection does not touch it.

## Suggested fix

1. Pin the opencode installer to a released version and verify a published checksum before
   executing it.
2. Pin `@anthropic-ai/claude-code@<exact-version>`.
3. Preferably, vendor both as digest-pinned container images and drop the network install
   entirely — that is the shape Principle IV asks for.
4. Independently: do not place a long-lived provider key in a job that runs an
   auto-approving agent (see 20260727-010). Use short-lived, scoped credentials.

## Regression test

Extend the `.github/` lint proposed in 20260727-004 to also fail on `curl … | bash`,
`curl … | sh`, and `npm install -g` without an `@<version>` pin inside any workflow `run:`
block.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S4).
- Same Principle IV root cause as 20260727-006 (mutable Action tags), 20260727-009 (Maven
  wrapper), and 20260727-002 (tor .deb).
