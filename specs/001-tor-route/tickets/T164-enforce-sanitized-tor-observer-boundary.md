---
id: "T164"
title: "Enforce the sanitized Tor observer boundary"
status: in-review
created: "2026-09-19"
last_updated: 2026-09-21
source: "specs/001-tor-route/tickets/T138-investigate-tor-observer-authority.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T138", "T162"]
parallel: false
files_budget: 24
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs:
  - ".specify/memory/constitution.md"
  - "specs/001-tor-route/contracts/foundation-boundaries.md §Deployment and authority"
  - "specs/001-tor-route/tickets/T138-investigate-tor-observer-authority.md"
  - "specs/001-tor-route/contracts/control-grpc.md §WatchEvents"
decision_refs: []
remediates: "T138"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T164: Enforce the sanitized Tor observer boundary

## Context

T138 found that the control plane's Java command allowlist is not an authority
boundary while the CP owns the Tor cookie and can reach `tor:9051`. Implement a
dedicated observer so the CP receives only sanitized health and cannot issue raw
Tor control commands. This ticket is the production fix for the T094a finding;
T165 owns integrated deployment evidence.

## Analysis

- **Must hold:** the CP has no Tor cookie, Tor-cookie group, raw ControlPort
  network path, or generic command channel; only the observer can authenticate
  to Tor; the CP-facing protocol is bounded and returns finite health tokens;
  failures are redacted and advisory; DP admission and route selection are
  unaffected.
- **Gated:** tests added here, compose/network structural gates, the control
  event contract, and `scripts/verify.sh`.
- **Residue:** production namespace packet and filesystem evidence, image
  provenance, and cross-profile deployment closure remain T165/T155 work.

## Acceptance

1. Write the regression probes first and record a failing result against the
   current direct-cookie shape. The probes must attempt stream/circuit
   observation, configuration, event-subscription, attachment, onion-service,
   signal, arbitrary-command and invalid/absent caller-authentication inputs
   only against disposable fakes; invalid callers receive no health token.
2. Implement the separate observer and CP-facing fixed health protocol from
   T138. Test the exact versioned framing, request/reply byte limits, EOF and
   deadlines, Tor-reply bounds, and one-query/no-queue limit before production
   code. Reject extra fields, oversized input and command text; never forward
   raw Tor replies or error details.
3. T162 removes the CP's cookie mount, Tor-cookie group and direct `tor:9051`
   reach while reserving the CP-only fabric. Install the observer's authenticated
   health socket on that fabric and give only the observer a narrow Tor-facing
   raw-control/cookie mount. Test CP→sanitized-health success, CP→SOCKS and
   CP→raw-control refusal, and observer recovery after Tor socket recreation;
   no generic proxy or raw Tor reply reaches CP.
4. Preserve the fixed `SidecarMonitor` event kind/detail vocabulary and
   advisory failure behavior. Reconcile `contracts/control-grpc.md` and its
   tests with T138's explicit health-to-event mapping before replacing the
   monitor; prove bootstrap-incomplete, malformed Tor reply, Tor timeout,
   observer-down and recovery cases cannot fabricate Tor exit/restart events.
   Prove CP or observer unavailability cannot stop authenticated DP routing or
   trigger Direct fallback.
5. Run the relevant tests and `scripts/verify.sh` green. Do not mark this
   ticket done until the tests-first red/green evidence and the changed-source
   review snapshot are retained.

## Out-of-scope

The integrated production-namespace proof, final release evidence, unrelated
Tor lifecycle controls, CONNECT identity changes, and any Constitution amendment
are owned by T165/T155 or later governed work.

## Notes

The observer is trusted for its narrow Tor-facing capability, but a compromised
CP must not be able to reach that capability. A health endpoint must not grow
into a command broker.

The high-complexity pre-implementation outline at
`specs/.handoffs/T164-OUTLINE.md` found the original 16-file budget too small
for the mandatory observer, key provisioning, contract tests, Compose
boundary, and same-change threat-model update. The 24-file budget reflects
that grounded inventory; the acceptance and out-of-scope boundaries are
unchanged. The outline was refined before production code or test edits.

Tests-first evidence (2026-09-21, baseline
`9ba618f96d4dfdc0c68549c5c74f9742e08d2049`): after adding the
rendered-Compose observer assertions and before changing Compose or source,
`bash tests/contract/compose/local_compose_test.sh` failed seven semantic
assertions: the observer service, its narrow Tor-control subpath, CP health
fabric, isolated key volume, network denial and named volume were absent.
After adding the Go observer protocol tests but before its implementation,
`go test ./cmd/tor-observer` failed to build because the required `config`
and `serve` symbols did not exist; the Compose failure is the independent
behavioral red result. The same Compose test later passed, the Go observer
suite passed with fake Tor and invalid caller/command inputs, and the Java
core test passed a real Java-client-to-Go-observer authenticated exchange.
The Docker-backed init test also exercised fresh provisioning, idempotence
and an observer-only upgrade preserving existing CP keys and pepper. The
final `verify.sh` result and review snapshot are recorded by the driver.

Round-1 review rework evidence (2026-09-21): both independent reviewers
found that Java client rejection and positive production boot wiring lacked
tests; Astra also found that a malformed Tor status containing
`PROGRESS=100` produced `READY`. Before the parser fix, the new fake-Tor
malformed-status cases failed with `READY/1` for garbage status, missing
`TAG`, missing `SUMMARY`, and an invalid `TAG`. After the fix, the Go suite
passes with valid `NOTICE` and `WARN` controls. The Java fake observer suite
exercises invalid identity, versions, framing, EOF, deadlines, and recovery.
For non-vacuity, temporarily bypassing the Java signature verification made
the wrong-pin probe fail (`READY` instead of `UNAVAILABLE`); temporarily
removing `monitor.start()` made the production-bootstrap audit probe fail
(zero rows instead of the required `sidecar_healthy` row). Both mutations
were restored before the green gate.
