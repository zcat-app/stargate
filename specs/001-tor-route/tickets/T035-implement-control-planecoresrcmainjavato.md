---
id: T035
title: 'Implement `control-plane/core/src/main/java/.../TokenLoader.java`'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T035
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T092, T093, T035a]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T035: Implement `control-plane/core/src/main/java/.../TokenLoader.java`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/core/src/main/java/.../TokenLoader.java` — parse `/etc/stargate/tokens.yaml` (**FR-017** — fixed-path config; same file FR-018's startup-only-reload contract reads) per data-model.md §1.1 validation table; for each token, draw a fresh 16-byte salt from `java.security.SecureRandom` (data-model.md §1.2 — per-token salt, never reused across tokens or across loads of the same token); argon2id-hash each plaintext using shared `Argon2idParams` (T011) with that salt; populate the per-token `TokenHash{hash, salt}` on the outgoing `ReloadTokensRequest`; zero the plaintext `byte[]` after hashing; log warnings without token bytes on validation failure. Diff the post-load label set against the previous generation's `enrolled_devices` rows (injected Panache repository) and emit, via `AuditLogService` (T036): `enrolled` for each label new this load, `revoked` for each label present in the previous generation but absent from the new file, `config_error` for each load failure (`detail_json.kind = "parse"|"validation"|"io"` per data-model.md §4 — `parse` on YAML syntax errors with the parser-reported line number, `validation` on per-entry format violations with the offending label, `io` on file-unreadable conditions like `AccessDeniedException`; no token bytes ever appear in `detail_json` or in the warning logs). Treat `FileNotFoundException`/`NoSuchFileException` as the legitimate first-boot state — log a single warning, write **no** audit row, push an empty `ReloadTokensRequest`, return cleanly (per FR-018: never throw on missing/unreadable file — the CP must come up healthy with an empty generation so the DP keeps serving per Principle II). Update `enrolled_devices` to match the new label set as part of the same transaction.

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**T092 amendment (2026-07-15) — consume the amended contract.**
`TokenLoader.java` must: (a) compute verifiers as `HMAC-SHA-256(pepper,
token)` reading the 32-byte pepper from `/etc/stargate/pepper.key`
(`data-model.md` §1.7), NOT Argon2id; (b) read+write the monotonic
generation from the persisted `token_generation` record and propose
`last + 1` (`data-model.md` §1.8); (c) on a stale `ReloadTokens` reply,
retry with `current_generation + 1` from the DP's response
(`data-model.md` §1.3); (d) on missing/unreadable/invalid/unparseable
`tokens.yaml`, log `config_error` and **NOT call `ReloadTokens`** (DP
keeps last-known) — only a successfully-parsed `tokens: []` revokes all
(`data-model.md` §1.6); (e) persist manual tokens to `configured_tokens`
(NOT `enrolled_devices`) — `enrolled_devices` is reserved for future
dashboard enrollment (`data-model.md` §1.9 / arch §6.1/§6.6). Tests-first
discipline is discharged by T093 (blocked_by T092); this ticket runs
after T093.
