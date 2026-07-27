---
id: 20260727-013-tests-first-unauditable
status: open
severity: major
principle: [VI, VII]
threat-model: n/a — process/governance surface
location: specs/001-tor-route/tickets/ (T011, T012, T019) + git history
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: null
decision-ref: null
---

# Principle VII (tests-first) is unauditable on 4 of 5 privacy-critical implementation/test pairs

## What the history shows

Constitution §VII requires, for any path touching DNS, routing, headers, authentication or
sidecar contracts, *"a test that demonstrates the privacy property **before the
implementation lands**"* — discipline **MANDATORY** — and states *"tests are not generated
post-hoc to fit existing code."* Principle VI requires the project be auditable.

First-add commit for every impl/test pair in the code that exists today:

| Ticket | `privacy_critical` | Implementation | Test | Verdict |
|---|---|---|---|---|
| T012a → T013 | true | `bind/check.go` @ `1067494` | `bind/check_test.go` @ `22cd134` | **tests-first, provable** |
| T011 | true | `auth/params.go` @ `0048f41` | `auth/params_test.go` @ `0048f41` | same commit — unprovable |
| T011 | true | `Argon2idParams.java` @ `0048f41` | `Argon2idParamsTest.java` @ `0048f41` | same commit — unprovable |
| T019 | true | `errortpl/template.go` @ `ba22b2b` | `errortpl/template_test.go` @ `ba22b2b` | same commit — unprovable |
| T012 | true | `V001__init.sql` @ `e3007c2` | `V001MigrationTest.java` @ `e3007c2` | same commit — unprovable |

## Why it matters

The project **has** the correct pattern and used it deliberately once: T012a was filed as its
own ticket and committed alone as `22cd134 "T012a bind-safety check unit test (test-first)"`,
with the implementation following 17 minutes later in `1067494`. That ordering is machine-
checkable forever, by anyone, without trusting anybody's recollection.

For T011, T012 and T019 the test and implementation landed in a single commit. The tests may
well have been written first — **the finding is that nobody can prove it**, on paths the
constitution designates MANDATORY.

Principle VII's own stated rationale is that, for AI-assisted development specifically, tests
act as *"an executable specification that the agent's output can be verified against, rather
than against vibes."* A test co-committed with its implementation cannot discharge that role:
it is indistinguishable from a test fitted to the code after the fact, which the principle
explicitly forbids. Principle VI's auditability requirement then fails too — the discipline
is real but leaves no evidence.

This is the highest-leverage governance finding of the audit because of what is still ahead:
**70 tickets remain, including the entire data-plane hot path (T042–T050)** — SOCKS5
listener, CONNECT handler, token verifier, control client, Tor forwarder, audit counters.
Those are the most privacy-critical files the project will ever contain, and the enforcement
mechanism for all of them is currently honour-based.

Related evidence that post-hoc test drift is a live risk, not theoretical: finding
20260727-003 documents two **passing** tests that pin a design the project rejected as a
Blocker — an executable mis-specification that survived a lock-step amendment.

## Suggested fix

Adopt the T012a/T013 split as the standing rule for every ticket with
`privacy_critical: true`: a test-only commit first (red), the implementation second (green).
Enforce it mechanically rather than by convention — a `.githooks/pre-commit` check (and a
`verify.sh` gate for the CI mirror) that rejects a commit adding both `X.go` and `X_test.go`
(or `Foo.java` and `FooTest.java`) when the active ticket is flagged privacy-critical.

Do this **before** T042–T050 land. Retrofitting proof of ordering after the fact is
impossible by definition.

## Regression test

The pre-commit hook is itself the mechanism; pair it with a contract test that feeds the hook
a synthetic staged pair and asserts a non-zero exit, so the gate cannot rot into a no-op
(cf. 20260727-007, where a gate silently stopped gating).

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding A2).
- 20260727-003 is a concrete instance of the drift this discipline exists to prevent.
