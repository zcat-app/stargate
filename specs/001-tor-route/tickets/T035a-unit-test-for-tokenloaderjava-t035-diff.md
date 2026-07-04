---
id: T035a
title: 'Unit test for `TokenLoader.java` (T035) diff logic and validation'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T035a
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T035]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
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

# T035a: Unit test for `TokenLoader.java` (T035) diff logic and validation

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Unit test for `TokenLoader.java` (T035) diff logic and validation — `control-plane/core/src/test/java/.../TokenLoaderTest.java`. Pure JVM unit test: in-memory fake of the `EnrolledDeviceRepository` (Panache repository for `enrolled_devices`), capturing fake of `AuditLogService` that records every `write(action, target, detailJson)` call, and a test-double `Argon2idHasher` that records the `byte[]` references it receives and exposes a post-call all-zero assertion (so the plaintext-zeroing rule from data-model.md §1.1 — "the `byte[]` cleared to zero before the next file entry is processed" — is testable without a real argon2id run; no `@QuarkusTest`, no SQLite, no DI runtime). Cases (each a separate `@Test`): (a) first-load with empty `enrolled_devices` and N valid tokens → N `enrolled` audit rows (one per label, `actor='tokens.yaml'`), no `revoked`, no `config_error`; `enrolled_devices` populated to match the new label set; (b) unchanged load (same labels as previous generation) → zero new audit rows; `enrolled_devices` unchanged; (c) one label removed from `tokens.yaml` → exactly one `revoked` row for that label; the corresponding `enrolled_devices` row is deleted; (d) one new label added → exactly one `enrolled` row; one new `enrolled_devices` row inserted; (e) mixed add+remove → both rows emitted in the same transaction (test asserts the call sequence to the fake repo is `BEGIN, delete(removed), insert(added), audit.write*, COMMIT` — no interleaved partial state visible to a concurrent reader); (f) malformed token entry (wrong length, non-hex chars) → `config_error` row with `detail_json.kind = "validation"` and `detail_json.label` set; no token bytes anywhere in `detail_json` or in the captured logs; the record is skipped, valid records continue to load (data-model.md §1.1 partial-failure tolerance); (g) unparseable YAML → `config_error` row with `detail_json.kind = "parse"` and a line number; (h) plaintext-zeroing: after (a) completes, the test asserts every `byte[]` ever handed to the test-double hasher is now all-zero (data-model.md §1.1's "`byte[]` cleared to zero" rule, which is the operationalisation of data-model.md §1.6's "plaintext tokens never persist outside `tokens.yaml`" entity invariant); (i) **file missing** (`FileNotFoundException` / `NoSuchFileException` thrown by the YAML reader) → loader returns an empty token list, emits **one** warning log line that mentions the path but contains no token-bytes context (there are none — the file did not open), writes **no** `config_error` audit row (the missing-file case is distinct from a parse/validation failure; per FR-018 the CP "logs a warning and proceeds with an empty token list" — no operator-actionable audit entry is created because the legitimate first-boot state is also "file does not exist yet"), and pushes an empty `ReloadTokensRequest` to the data plane via the injected fake `ReloadTokensClient` so callers observe the same RPC shape as a successful load; (j) **file unreadable** (`AccessDeniedException` thrown on open, e.g. the operator-mounted file has wrong group/mode) → same outcome shape as (i) for token-list and RPC, but emits a single **`config_error`** audit row with `detail_json.kind = "io"` and `detail_json.line = null` (matching the §4 schema; `io` is the kind that distinguishes a permissions misconfiguration from a missing file — `line` is null because there is no parser context) so the operator sees a distinct signal from "file just isn't there yet" — the audit log is the operator's path to noticing a permissions misconfiguration. In both (i) and (j), the loader MUST NOT throw (the CP would crash-loop on a missing/unreadable file otherwise, defeating Principle II's "data plane keeps serving with last-known token list" property; instead the CP comes up healthy with an empty generation and the DP returns `AUTH_REQUIRED` on all requests per FR-018). Pairs with T035 (impl); T035a MUST be authored and failing before T035 lands. Principle VII applies because `tokens.yaml` is the operator-facing public CP config surface and the diff-derived audit log is operator-visible — together they fall under "Public API surfaces (REST, gRPC contracts)" in the principle's discipline table (treating the operator-facing config file + audit log as a public-surface pair).

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
