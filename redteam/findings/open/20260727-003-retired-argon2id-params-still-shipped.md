---
id: 20260727-003-retired-argon2id-params-still-shipped
status: open
severity: major
principle: [VI, VII]
threat-model: 5.14
location: data-plane/internal/auth/params.go:5-36
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: 'SECURITY-DECISIONS.md 2026-07-15 — Bearer-token verifier: HMAC-SHA-256 + install-time pepper (T092)'
---

# Retired Argon2id verifier parameters still ship on both planes, documented as authoritative and pinned green by tests

Found independently by both the security and performance reviewers in the same run.

## What the code does

`data-plane/internal/auth/params.go:5-8` states that the Argon2id parameter constants below
*"are the v1 design point from `specs/001-tor-route/data-model.md` §1.5"*, and declares at
`:24-36`: `Argon2idMemoryKiB = 64 * 1024`, `Argon2idParallelism = 4`, `Argon2idSaltLen = 16`.

`control-plane/core/src/main/java/app/zcat/stargate/auth/Argon2idParams.java:7-8` carries the
same citation and adds at `:21-22`: *"These are compile-time constants; the hashing code that
consumes them lands in a later task."*

`data-model.md` §1.5 — the cited authority — is now titled *"Verifier construction —
HMAC-SHA-256 over the install-time pepper"*, declares `salt = NONE`, and states:

> the 64 MiB / parallelism-4 Argon2id allocation is an unbounded memory-DoS vector … 200
> concurrent one-token auths allocate ~200 × 64 MiB = 12.8 GiB and any local process can
> reach the loopback proxy to trigger it.

Both planes carry **passing** tests that pin the retired values against that citation:
`data-plane/internal/auth/params_test.go:8-34` (`TestArgon2idParamsMatchSpec`, verified green
via `go test ./internal/...`) and
`control-plane/core/src/test/java/.../Argon2idParamsTest.java` (six `assertEquals` with
`"data-model.md §1.5: …"` failure messages). They sit in the same packages as the replacement
contract tests (`hmac_verifier_test.go`, `TokenLifecycleContractTest.java`), so an
implementer opening `data-plane/internal/auth/` sees both designs — one of which is
documented as "the v1 design point".

## Why it leaks

Constitution Principle VI requires critical code to carry comments linking to the principle
or spec that motivates the design; here the link points at a section that says the opposite.
Principle VII makes tests the executable specification; here two green tests specify a design
the project rejected as a Blocker.

Concretely: T044's implementer — or the eventual Java-side token-hashing implementer, who has
no ticket telling them otherwise — reads *"the hashing code that consumes them lands in a
later task"*, imports `golang.org/x/crypto/argon2` or `argon2-jvm`, and wires
`Argon2idMemoryKiB`. That reinstates sol-review **B5 (Blocker)** exactly: 200 concurrent
unauthenticated CONNECTs on loopback port 8881 allocate ~12.8 GiB and OOM the data plane.
`golang.org/x/crypto/argon2.IDKey` allocates its full memory block up front, so the flood
needs no cleverness. The mitigation T092 bought is undone by a comment that survived the
amendment.

## Governance defects that produced this

- **`specs/001-tor-route/tickets/T011-...md:4` is `status: done`, but its acceptance
  criterion #1 is now false:** *"The five Argon2id parameter values match data-model.md §1.5
  exactly."* §1.5 contains no Argon2id values. A done ticket's artefact no longer satisfies
  its own acceptance.
- **No ticket owns the Java-side removal.** `T044-implement-data-planeinternalauthtokengo.md:66-70`
  (status `pending`) owns only the Go removal.
  `grep -rln "Argon2idParams.java\|Argon2idParamsTest" specs/001-tor-route/tickets/` returns
  **only T011**.
- **T092's lock-step amendment missed them.** `SECURITY-DECISIONS.md:220` ("Downstream
  artefacts amended in lock-step (acceptance #7)") lists eleven artefacts; none of these four
  files appear.

## Suggested fix

Delete all four files now — `data-plane/internal/auth/params.go`, `params_test.go`,
`control-plane/core/src/main/java/app/zcat/stargate/auth/Argon2idParams.java`,
`control-plane/core/src/test/java/app/zcat/stargate/auth/Argon2idParamsTest.java` — rather
than deferring the Go half to T044 and the Java half to nobody. The HMAC contract tests that
replace them already exist and pass on both planes (`hmac_verifier_test.go`,
`TokenLifecycleContractTest.java`), so coverage does not regress. File a ticket for the
Java-side removal if process requires one, but do not leave the artefact live meanwhile.

**Weaker fallback**, if the constants must survive until T044 lands: invert both header
comments to *"SUPERSEDED by T092 — do NOT consume; see data-model.md §1.5 for why Argon2id
was retired"*, and rename both tests to `TestRetiredArgon2idParamsAreNotConsumed` or
equivalent. This is strictly worse than deletion — it keeps a loaded footgun in the auth
package — and should be chosen only if something outside the reviewer's visibility depends
on the symbols.

Either way, correct T011's acceptance criterion or reopen it, and add the four files to
T092's lock-step artefact list.

## Regression test

Add a grep-gate under `tests/contract/secret-scan/` (or the existing workflow gate) asserting
that no file under `data-plane/**` or `control-plane/*/src/main/**` references `argon2` /
`Argon2id`. That gate fails today, passes after the deletion, and prevents the retired design
from re-entering via a future copy-paste — the exact failure mode T092's incomplete lock-step
amendment left open.

## Related

- `SECURITY-DECISIONS.md` "2026-07-15 — Bearer-token verifier: HMAC-SHA-256 + install-time
  pepper (T092)"; its acceptance-#7 artefact list at `:220` is the omission that produced this.
- sol-review B5 (Blocker) is the finding that would be reinstated.
- `THREAT-MODEL.md` §5.14 documents the replacement design's residue.
- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S3/C2).
