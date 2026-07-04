---
id: T011
title: 'Author shared Argon2id parameter constants'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T011
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: ['data-model.md#1.5', 'constitution.md#VII']   # filled at /start
decision_refs: []
reviews: { round: 1, date: 2026-07-04, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T011: Author shared Argon2id parameter constants

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author shared Argon2id parameter constants — `data-plane/internal/auth/params.go` and `control-plane/core/src/main/java/.../auth/Argon2idParams.java` — with the exact values from data-model.md §1.5 (`time=3, memory=64MiB, parallelism=4, hashLen=32, saltLen=16`); both files reference data-model.md §1.5 in their header comment.

## Analysis

**Must hold** (Constitution Principle VII lands here as concrete properties):

1. The five Argon2id parameter values match data-model.md §1.5 exactly —
   `time=3, memory=64 MiB (= 65536 KiB), parallelism=4, hashLen=32 bytes,
   saltLen=16 bytes`. Any other value is a contract violation that
   breaks per-request auth (data-model.md §1.5: "fast enough that
   per-request overhead is negligible … slow enough that brute-forcing a
   leaked snapshot file is non-trivial").
2. **Cross-plane equality.** Go (`data-plane/internal/auth/params.go`)
   and Java (`control-plane/core/.../auth/Argon2idParams.java`) declare
   the *same* numeric values. data-model.md §1.5: "mismatch is a
   contract violation surfaced at handshake."
3. **Unit disambiguation.** Argon2id memory is conventionally in KiB
   (`golang.org/x/crypto/argon2.IDKey` and `argon2-jvm` both take KiB);
   64 MiB = 65536 KiB. The constant must make the unit unambiguous to
   prevent the 64-vs-65536-confusion class of bug.
4. Both files cite data-model.md §1.5 in their header comment (per the
   task body).
5. Apache 2.0 SPDX header present (Principle VI).

**Gated** (verify.sh catches fail-closed):

- License header → `scripts/check-license-headers.sh` (Gate 1).
- Go file compiles, `go vet` clean → Gate 2.
- Java file compiles under the reactor → Gate 3 (now active since Java
  sources exist post-T010).
- Cross-plane equality of values is **not** auto-gated.

**Residue** (no gate catches; addressed by §Acceptance tests):

- Semantic correctness of each value vs the spec — only a hard-coded
  spec-value test catches drift in either direction.
- Unit confusion (KiB vs MiB vs bytes) — only a test asserting
  `MemoryKiB == 64*1024` catches it.
- Cross-plane drift — there is no shared source-of-truth file both
  planes read; the two constants files are independent. The two per-plane
  unit tests both pin to the same spec values, so a drift in either
  surfaces as a test failure on the drifting plane. No standing
  cross-plane equality gate exists in v1 (acceptable: the values are
  immutable in v1; a future feature bumping them is the natural trigger
  for adding one).

## Acceptance

**Named tests (Principle VII — privacy-critical path: authentication
parameters; tests must exist and fail before impl lands):**

- `data-plane/internal/auth/params_test.go` — table-driven; asserts each
  Go constant equals its data-model.md §1.5 value:
  `Time==3`, `MemoryKiB==64*1024`, `Parallelism==4`, `HashLen==32`,
  `SaltLen==16`.
- `control-plane/core/src/test/java/app/zcat/stargate/auth/Argon2idParamsTest.java`
  — JUnit equivalent assertions on `Argon2idParams.TIME`,
  `MEMORY_KIB`, `PARALLELISM`, `HASH_LEN`, `SALT_LEN`.

**Runnable command:** `bash scripts/verify.sh` GREEN (both unit tests
execute: Go gate runs `go test ./...`, mvnw gate runs `mvn verify`).

## Out-of-scope

- Argon2id *computation* (hashing) — lands in later auth-impl tasks
  (per `data-plane/tools.go`: T013 + control-plane wiring). This ticket
  ships constants only; no `golang.org/x/crypto/argon2` or
  `de.mkammerer:argon2-jvm` dependency is added.
- Cross-plane equality gate (a single shared constants file both planes
  read). v1 values are immutable; deferred until a future feature
  actually bumps them.

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
