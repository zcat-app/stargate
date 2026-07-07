---
id: T083
title: 'Sweep stale SECURITY-DECISIONS.md prose + V001 sidecar_restart'
status: pending
created: 2026-07-05
last_updated: 2026-07-05
source: derived-from-T018-redteam  # not in tasks.md; filed from T018's redteam r3 INFO-1 + codereview F1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T018]   # T018 fixed spec.md; this ticket sweeps the same stale-prose pattern across the rest of the feature tree
parallel: false
files_budget: 4
privacy_critical: false   # paperwork-class doc drift; canonical values gated at artifact layer
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §6.5 (audit_log enum — the canonical source-of-truth in the arch spec)
  - specs/001-tor-route/data-model.md §4 (the five-action authoritative vocabulary)
decision_refs:
  - SECURITY-DECISIONS.md §"2026-07-04 — Tor sidecar trust rationale (FR-015)" (T017 entry — exists, not TODO)
constitution_refs:
  - "V: Honest Threat Model"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T083: Doc-hygiene sweep — stale "once that file is authored" prose + spurious V001 `sidecar_restart`

## Context

Filed from T018's redteam r3 (CLEAN verdict) INFO-1 + T018's codereview
r1 F1 follow-up. T018 amended `specs/000-architecture/spec.md` in lock-
step with the SECURITY-DECISIONS.md entries (T017 Tor + T017a docker-
socket-proxy) and landed three sibling-paragraph fixes for the stale
"once that file is authored" pattern (§7 sibling at MAJ-1, §16.1
Property-bought at MAJ-2, §15 #1 at MAJ-3). The redteam r3 explicitly
flagged that two OUTSIDE-of-spec.md artifacts carry the same stale
pattern and are NOT T018 defects (T018's mandate is spec.md only);
this ticket picks them up. T018's codereview r1 F1 also filed a
follow-up on `V001__init.sql:67` carrying a spurious `sidecar_restart`
enum entry that T012 owns but is already done, so this ticket folds
the SQL fix in.

`privacy_critical: false` because every drift here is paperwork-class
prose / comment text; the canonical values (the five-action enum, the
existing SECURITY-DECISIONS.md rationale) are gated at the artifact
layer (SQL migration + T036 AuditLogService at runtime, T017
`tor_entry_test.sh` for the rationale entry's existence).

## Analysis

Built at filing time. Quick-pass (non-privacy-critical per the
`privacy_critical: false` flag).

### Must hold

- **M1 — `specs/001-tor-route/checklists/requirements.md:94-98`** (the
  "Remaining owed (not blocking `/speckit-plan`)" bullet) still names
  the SECURITY-DECISIONS.md Tor trust-rationale entry as owed and
  frames the file as not-yet-authored. Verifiably false: T017's entry
  exists (`SECURITY-DECISIONS.md` §"2026-07-04 — Tor sidecar trust
  rationale (FR-015)"; cross-checked by `tests/contract/security-
  decisions/tor_entry_test.sh`); the file exists at repo root; the
  Constitution v1.1.0 Sync Impact Report no longer lists it as TODO.
  T083 rewrites the bullet to honestly mark the Tor entry as authored
  and remove the inline-as-fallback framing.
- **M2 — `specs/001-tor-route/research.md:229`** (the closing
  "Follow-up" of §6 Extension bearer-token storage) still reads
  "SECURITY-DECISIONS.md to carry the rationale once that file is
  authored." Same stale shape; T083 rewrites to point at the existing
  entry.
- **M3 — `control-plane/persistence/src/main/resources/db/migration/V001__init.sql:67`**
  carries a spurious `sidecar_restart` entry in the `audit_log.action`
  enum comment (mirrors the drift T018 just fixed in spec.md §6.5).
  Verifiably false: `data-model.md §4` enumerates exactly FIVE actions
  (`enrolled, revoked, config_error, sidecar_healthy, sidecar_unhealthy`);
  T036 AuditLogService contract says "five fixed-vocabulary actions";
  T074 makes RESTARTED event-only and explicitly writes no audit-log row.
  T083 drops `sidecar_restart` from the comment so the rendered schema
  matches `data-model.md §4` and `spec.md §6.5` (post-T018). The
  runtime enum is the SQL column type (`TEXT`), so no migration is
  needed — only the comment is corrected.

### Gated

- M1/M2 prose drift: not currently gated by a contract test (T018 R3
  documents spec-prose referencing FR-015/SECURITY-DECISIONS.md is
  reviewer-enforced coupling; T017's `tor_entry_test.sh` gates the
  entry's existence, not other artifacts' references to it).
- M3 SQL enum: the enum is `TEXT` (free-form column), not a CHECK
  constraint — no schema-level gate exists. T036's AuditLogService
  runtime test gates which actions the CP actually emits; the SQL
  comment is informational.

### Residue

- **R1 — whole-tree stale-prose sweep.** T083 sweeps the three flagged
  locations. A more thorough sweep (whole repo grep for
  `once that file is authored|outstanding follow-up|owed for both`)
  might surface other incidental mentions in docs/historical PR
  descriptions; T083 is scoped to the three the redteam flagged plus
  any exact-match grep hits in `specs/` and `docs/`. Outside-scope:
  historical handoff files under `specs/001-tor-route/.handoffs/`
  (gitignored, append-only session records — they capture what was
  true at write time; not amended retroactively).

## Acceptance

T083 is a documentation-only sweep. Named tests:

1. **EXISTING: `tests/contract/security-decisions/tor_entry_test.sh`**
   (T017) MUST remain GREEN — T083 does not touch SECURITY-DECISIONS.md.
2. **EXISTING: `tests/contract/security-decisions/docker_socket_proxy_entry_test.sh`**
   (T017a) MUST remain GREEN.
3. **EXISTING: `tests/contract/arch/docker_socket_proxy_section_test.sh`**
   (T018) MUST remain GREEN — T083 does not touch `specs/000-architecture/spec.md`.

### Behavioral assertions (PR-time verification at `/start`)

- `specs/001-tor-route/checklists/requirements.md`: the "Remaining owed"
  bullet is either (a) removed entirely (preferred — Tor entry IS
  authored, no remaining owed) or (b) rewritten to honestly point at
  the T017 entry.
- `specs/001-tor-route/research.md:229`: closing sentence rewritten to
  reference the existing T017 entry rather than framing the file as
  future.
- `control-plane/persistence/src/main/resources/db/migration/V001__init.sql:67`:
  `sidecar_restart` removed from the enum comment so the rendered
  vocabulary matches `data-model.md §4` and `spec.md §6.5` exactly:
  `enrolled, revoked, config_error, sidecar_healthy, sidecar_unhealthy,
  bridge_toggle, export, import, wipe`.
- Whole-`specs/` grep for `once that file is authored|outstanding
  follow-up|owed for both` returns zero matches after T083 lands
  (regression guard; T018 already enforced this for spec.md).

### Runnable command

```
scripts/verify.sh
```

Expected after T083 lands: PASS=8 SKIP=2 FAIL=0 (no new test; existing
tests remain green; T083 is paperwork-class doc drift).

## Out-of-scope

- **Do NOT amend `specs/000-architecture/spec.md`** — T018 already did
  the spec.md sweep (§7 sibling, §15 #1, §16.1 Property-bought). Any
  residual spec.md drift would be a T018 follow-up, not T083.
- **Do NOT amend `SECURITY-DECISIONS.md` or `THREAT-MODEL.md`** — T082
  owns THREAT-MODEL; SECURITY-DECISIONS is append-only (T017/T017a own
  their entries).
- **Do NOT add a contract test gating the SQL comment vs. `data-model.md
  §4`.** The runtime enum is the SQL column type (`TEXT`); T036 gates
  which actions are emitted. Comment-vs-data-model drift is reviewer-
  enforced coupling (paperwork-class).
- **Do NOT sweep `specs/001-tor-route/.handoffs/`** — gitignored
  session handoffs are append-only records of what was true at write
  time; they are not retroactively amended.
- **Do NOT touch `sidecar_restart` references in `tasks.md`** if any
  exist — tasks.md is regenerated by `/speckit-tasks` and survives
  regeneration as the spec-kit plan; a hand-edit would be overwritten.

## Notes

Derived by hand from T018's redteam r3 audit doc + T018 codereview r1
F1 follow-up note on 2026-07-05. Not in tasks.md (T082 set the
precedent: redteam-filed follow-ups land as standalone tickets under
`specs/001-tor-route/tickets/` and are picked up by `scripts/next-task.sh`
once their `blocked_by` clears).
