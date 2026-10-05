---
id: 20260727-006-actions-pinned-to-mutable-tags
status: closed
severity: major
principle: [IV, VI]
threat-model: n/a — CI/supply-chain surface
location: .github/ (13 `uses:` refs across 3 files)
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: 0cd5188
decision-ref: null
remediation-ticket: T141
closed-date: 2026-10-05
closed-by: T141 pins every external action by full commit SHA and ci_inputs_test.sh fails on any mutable external uses reference
---

# Every GitHub Action is pinned to a mutable tag, not a commit SHA

## Closure — 2026-10-05

Every external `uses:` across agent-task, verify, docker-cadence and
setup-toolchain is a 40-hex SHA. Later workflows added by T191 follow the same rule and are
discovered by the same test. Whether the gitleaks binary fetched by the pinned action is
digest-checked is owned by T199 item 4.

## What the code does

All 13 `uses:` references resolve to moving tags:

- `actions/checkout@v4` — `agent-task.yml:114`; `verify.yml:35,79,96`
- `actions/github-script@v7` — `agent-task.yml:209`
- `actions/setup-go@v5`, `actions/setup-java@v4`, `actions/setup-python@v5` —
  `.github/actions/setup-toolchain/action.yml:18,24,31`; `verify.yml:97`
- `actions/upload-artifact@v4` — `verify.yml:54`
- **`gitleaks/gitleaks-action@v2`** — `verify.yml:83`

```
$ grep -rn 'uses:' .github/ | grep -vE '@[0-9a-f]{40}'
(13 hits)
```

## Why it leaks

`@v4` / `@v2` are tags the upstream owner — or anyone who compromises the upstream repo —
can repoint at will. This is a recurring real-world compromise class (e.g. the
`tj-actions/changed-files` incident), and a moving tag leaves no audit anchor to detect it.

`gitleaks/gitleaks-action@v2` is the most sensitive: it is third-party, it runs in the
`secret-scan` job with a `GITHUB_TOKEN`, and it is the **authoritative** secret gate. A
repointed tag can be made to exfiltrate the very secrets it is supposed to catch, or to
report a clean scan unconditionally — a silent false-green on the project's own leak defence.

Constitution Principle IV requires external components be referenced by digest, never a
mutable tag; Actions are external components. Principle VI requires the gate be auditable.

## Suggested fix

Pin every `uses:` to a full 40-hex commit SHA with a trailing `# vX.Y.Z` comment for
readability, and let Renovate propose SHA bumps through the Principle IV
pinned-tested-manually-promoted flow.

## Regression test

Add a CI lint (or extend `scripts/ground-check.sh`) that fails on any `uses:` not matching
`@[0-9a-f]{40}`. One grep, permanently enforced.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S5).
- Same Principle IV root cause as 20260727-005, 20260727-009, 20260727-002.
