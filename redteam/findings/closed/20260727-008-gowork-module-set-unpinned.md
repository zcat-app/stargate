---
id: 20260727-008-gowork-module-set-unpinned
status: closed
severity: major
principle: [VI, VII]
threat-model: n/a — build-integrity surface
location: scripts/go-workspace-gate.py:75-101 (consumed by scripts/verify.sh:169-175)
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: 5293b7d
decision-ref: null
remediation-ticket: T139
closed-date: 2026-10-05
closed-by: T139 adds a mandatory module set to go-workspace-gate.py that fails when data-plane, proto, tests/contract, tests/internal/loginvariants or tests/integration is omitted from go.work
---

# Deleting one `go.work` line silently drops a whole module — including the data plane — from the Go test gate

## Closure — 2026-10-05

`scripts/go-workspace-gate.py` FAILs with "mandatory module(s)
omitted from go.work". `required_coverage_test.sh` removes each module in turn and asserts the
failure. The suggested CODEOWNERS gate was not adopted.

## What the code does

`go-workspace-gate.py:75-101` (`discover_modules`) reads the `use (…)` block of `go.work` and
tests exactly the modules listed there. **Nothing asserts a required set.** Removing
`./data-plane` from `go.work` drops the entire privacy-critical data plane from the Go test
gate; the gate then reports "discovered N module(s)" for the smaller N and stays GREEN.

`tests/contract/verify_discovery_test.sh` validates the gate's internal verdict logic against
synthetic sandboxes, but never asserts that the *real* repo's `go.work` still contains
`./data-plane`, `./proto`, and the contract/integration modules.

## Why it leaks

A PR editing one line of `go.work` — plausibly disguised as a refactor, or produced by an
agent commit — stops the data-plane test suite from running, **including the T034 integration
test asserting no DNS query is emitted for any `*.onion` name**. That test is the regression
line for a Principle I/III invariant, and it would go dark with no red signal anywhere.

Constitution Principle VI (machine-checked gate) and Principle VII (tests are the regression
line for privacy-critical paths) both fail: a one-line edit disables the regression line.

Discovery-driven gating is the right default — it means new modules are covered
automatically, with no gate edit. The defect is the absence of a *floor*: discovery should be
able to add modules but never to silently remove the ones that must always be present.

## Suggested fix

Add a required-modules manifest asserted by `verify.sh` (or by the discovery gate itself):
fail if `./data-plane`, `./proto`, `./tests/contract`, `./tests/integration` and
`./tests/internal/loginvariants` are absent from `go.work`. Keep discovery for everything
beyond the floor.

Consider gating `go.work` edits behind explicit review (CODEOWNERS), on the same reasoning
that makes the constitution itself amendment-gated.

## Regression test

Extend `verify_discovery_test.sh` with a case that removes `./data-plane` from a fixture
`go.work` and asserts the gate FAILs rather than reporting a smaller discovered set.

## Related

- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S7).
- Same "green gate can be silently hollowed" class as 20260727-007.
