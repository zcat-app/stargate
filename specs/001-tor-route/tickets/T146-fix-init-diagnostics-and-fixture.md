---
id: "T146"
title: "Correct init timeout diagnosis and isolate its fixture"
status: in-review
created: "2026-09-12"
last_updated: 2026-09-25
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T088", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: false
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T088"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T146: Correct init timeout diagnosis and isolate its fixture

## Context

Existing finding 20260727-012: misleading network diagnosis and fixed 8881 fixture remain; the historical missing-trap allegation is refuted.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Report timeout as an observed readiness failure without asserting host VPN/firewall cause unsupported by evidence.
2. Make concurrent disposable init fixture runs use non-colliding resources/ports while preserving production loopback port requirements.
3. Force fixture failure and assert its already-existing EXIT/INT/TERM cleanup removes only owned resources; reproduce any remaining leak before altering teardown.
4. Run fixture tests and scripts/verify.sh; record Constitution VII smoke-test scope.

## Out-of-scope

Host network/VPN changes, production mount repair (T123), or Tor bootstrap readiness (T124).

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

Constitution VII smoke-test scope: `init_probe_test.sh` injects a timed-out
loopback connect and checks only the operator message and exit 50. The Docker
fixture tests exercise assigned loopback ports, simultaneous projects, and an
injected failure after provisioning; they do not identify a host VPN or
firewall cause, validate Tor bootstrap, or prove production bind safety.
The forced failure reproduced a leak of two project-labelled observer volumes
that the fixture did not mount; cleanup now removes those owned volumes after
Compose teardown and leaves a foreign-labelled volume intact.
The failing and passing Docker outputs, with their source states, are retained
in `specs/001-tor-route/evidence/T146-fixture-cleanup.md`. The INT and TERM
traps contain only `exit 130` and `exit 143`; Bash then runs the same EXIT
trap and `cleanup()` body exercised by the forced-failure probe. The probe
does not separately deliver signals.
