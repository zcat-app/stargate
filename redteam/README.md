# Red-team findings worklist

Active worklist of security/privacy findings produced by the
`stargate-redteam` subagent (Constitution Principle VIII). The per-run
audit doc lives in `../reviews/`; this directory holds the **mutable**
worklist a fixer session works through.

## Layout

```
findings/
  open/      One file per unresolved Blocker or Major finding.
  closed/    Findings whose fix has landed. `fix-commit` set in frontmatter.
  accepted/  Findings accepted as residual risk. `decision-ref` points to
             an anchor in ../SECURITY-DECISIONS.md.
```

Minor and Info findings are **not** worklist items — they live in the
audit doc under `../reviews/` only.

## File format

Each finding has YAML frontmatter and a body. See
`.claude/agents/stargate-redteam.md` § "Artifact 2" for the canonical
schema. Required frontmatter:

- `id` — `YYYYMMDD-NNN-<slug>` matching the filename.
- `status` — `open` | `closed` | `accepted`.
- `severity` — `blocker` | `major`.
- `principle` — list of constitution principle numbers.
- `location` — `path/to/file:line`.
- `first-seen-run` — `YYYYMMDD-<short-commit>` of the run that filed it.
- `fix-commit` — commit SHA that closes it (null until status: closed).
- `decision-ref` — `SECURITY-DECISIONS.md` anchor (null until accepted).

## Fixer workflow

Fresh Claude Code session pointed at this directory. Per session:

1. **Triage new files.** `redteam-redteam` does not dedup. Walk new
   files in `open/` against existing entries in `open/`, `closed/`, and
   `accepted/`:
   - If the new file describes the same `location` + principle as a file
     already in `closed/` or `accepted/`, **delete the new file** —
     reconciliation is the fixer's job, not the agent's.
   - If the new file duplicates one already in `open/`, merge useful
     context into the existing file and delete the new one.
   - Otherwise leave it as a fresh open finding.
2. **Address each open finding.** Read the file, implement the suggested
   fix (or a better one), land the regression test described in the file
   (Principle VII), commit.
3. **Close the finding.** Move the file from `open/` to `closed/`. Set
   `status: closed` and fill `fix-commit` with the closing commit SHA.
4. **Or accept the finding.** If the fix is out of scope or the residual
   risk is acceptable, append an entry to `../SECURITY-DECISIONS.md`
   (append-only per Principle VIII), then move the file to `accepted/`,
   set `status: accepted`, and fill `decision-ref` with the anchor.

Never edit a file in `closed/` or `accepted/` to reopen it. If the same
leak resurfaces in a later run, `stargate-redteam` will file a new
finding under a new `id`, and the fixer triages it afresh.

## Why this is separate from `reviews/`

`reviews/redteam-YYYYMMDD-<sha>.md` is an **immutable per-run audit
snapshot** — including the "verified absent" regression line that proves
which checklist categories the agent actually checked on that commit.
That doc is the audit trail and never mutates.

`redteam/findings/` is a **mutable worklist** with status transitions
across runs. Conflating the two would either lose the regression line
(if the audit doc became mutable) or force the fixer to parse a doc
instead of globbing a folder (if the worklist lived inside the audit doc).

The fixer reads `redteam/findings/`; auditors read `reviews/`.
