# Bootstrap prompts

These are **single-purpose prompt files** for foundational artefacts of the
Stargate project. Each one is self-contained and designed to be pasted as the
first user message in a fresh Claude Code session (in this project directory)
to produce one specific artefact with a clean context window.

## Why this exists

The conversation that produced `.specify/memory/constitution.md` and `CLAUDE.md`
accumulated a lot of design context (~170k tokens). Each downstream artefact
(architecture spec, threat model, etc.) does not need that full history —
only the **constitution + the artefact's specific brief**. These prompt files
hand that brief to a fresh session.

## How to use

1. Open a fresh Claude Code session in this project directory
   (`/home/ubuntu5/Projects/quarkus-projects/stargate/`).
2. Paste the contents of the relevant prompt file as your first message.
3. Let Claude read the constitution and produce the artefact.
4. Review the output; iterate in that session if needed.
5. Close the session when the artefact lands.

## Dependency graph

```
                ┌──────────────────────────────┐
                │  .specify/memory/constitution.md  │  (done)
                └──────────────┬───────────────┘
                               │
                               ▼
                  ┌──────────────────────────┐
                  │ 01-architecture-spec.md  │  (do FIRST)
                  └──────────────┬───────────┘
                                 │
            ┌────────────────────┼────────────────────┬────────────────┐
            ▼                    ▼                    ▼                ▼
  ┌──────────────────┐ ┌────────────────────┐ ┌─────────────────┐ ┌──────────────┐
  │ 02-threat-model  │ │ 03-contributing    │ │ 04-redteam-agent│ │ 05-perf-agent│
  └──────────────────┘ └────────────────────┘ └─────────────────┘ └──────────────┘
            │                    │                    │                │
            └────────────────────┴──────┬─────────────┴────────────────┘
                                        ▼
                       ┌─────────────────────────────────┐
                       │ 06-tor-route-feature-spec.md    │  (do LAST)
                       └─────────────────────────────────┘
```

- **01 first** — pins concrete decisions everything else references.
- **02–05 can run in parallel** in separate fresh sessions after 01 lands.
- **06 last** — uses `/speckit-specify` and benefits from all prior artefacts.

## Update policy

You generally do **not** need to update prompt files between steps. Each prompt
says "read the constitution and any artefacts that exist now" rather than
embedding their content. As long as constitution + downstream docs are the
source of truth, prompts stay valid.

**Exceptions where you should update:**

- If executing step 01 produces a decision that contradicts a downstream prompt's
  assumption (rare — the prompts are kept generic).
- If you want to scope a fresh session more narrowly than the prompt file
  currently does.

A useful pattern: **before pasting prompt N, skim it for any line that mentions
something that may have changed.** A 30-second scan beats discovering drift
mid-run.

## When you're done with a prompt file

Delete it, archive it, or leave it as historical record of how the project
was bootstrapped — your call. They're tracked in git so contributors can see
the AI-assisted authoring path. If they become clutter, move to
`docs/bootstrap-history/` or delete.
