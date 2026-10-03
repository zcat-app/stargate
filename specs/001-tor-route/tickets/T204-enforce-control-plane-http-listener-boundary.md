---
id: "T204"
title: "Enforce control-plane HTTP listener boundary at startup"
status: pending
created: "2026-10-03"
last_updated: "2026-10-03"
source: "T155 resumed cumulative CP/browser CPB-M2; independently falsified 2026-10-03; approved next-scope-after-T203.md section C"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T040", "T041", "T152", "T162", "T167", "T185", "T187", "T203"]
parallel: false
files_budget: 34
privacy_critical: true
complexity: high
risk: high
round_cap: 3
remediates: "T040"
spec_refs:
  - "specs/001-tor-route/contracts/foundation-boundaries.md §Deployment and authority"
  - "specs/001-tor-route/contracts/control-grpc.md §Socket topology"
  - "specs/001-tor-route/spec.md §Assumptions: No Quarkus dashboard UI yet"
  - "specs/001-tor-route/plan.md §Control-plane scope"
  - "THREAT-MODEL.md §3.1 Local mode"
constitution_refs:
  - "II: Plane Separation and authenticated local management"
  - "III: actor/traffic matrix and operational-record minimization"
  - "IV: pinned executable inputs"
  - "V: honest boundary and evidence statements"
  - "VII/VIII: tests-first, independent review and exact-candidate evidence"
  - "Tech Stack / Deployment Model: actual CP listeners, supported IP families and startup refusal"
decision_refs:
  - "2026-10-03 user approved full next scope after T203: CP-listener and hardening-record repairs, T117 absorption, DNS-capture filing, then T155; conforming repairs only, no policy waiver"
  - "CPB-M2: falsify-2-cp-browser.md in .scratch/tmp/T155/redteam-a4r; pinned Quarkus 3.33.1 production-default bytecode corroborates wildcard host, actual packaged namespace observation remains required"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T204: Enforce control-plane HTTP listener boundary at startup

## Context

T040 introduced the headless CP's HTTP health stub and T041 packages and starts it.
The production configuration has no enforced listener boundary. The hash-matched
Quarkus 3.33.1 library selects `0.0.0.0` in normal mode; Compose's `network_mode: none`
and absence of a published CP port do not satisfy the constitution's express
loopback-only rule for actual CP health listeners. CPB-M2 survives independent
falsification. Exact packaged listener and IPv6 observations remain to be captured;
this ticket does not claim demonstrated public ingress or a remote authentication bypass.

T203 has repaired the observer authority boundary. This focused repair supplies fresh
CP listener evidence to T155 and blocks T078 and T190's related endpoint wording.
Completed T040/T041 remain historical lineage. No T155 dependency is added to T204.

## Analysis

- **Must hold:** every CP HTTP/admin/health listener the supported production artifact
  can activate is absent under an enforced no-listener design, or binds only the
  explicitly supported/tested loopback address in Local. Nonconforming effective
  configuration fails before an invalid listener can accept traffic, on initial boot
  and restart. No container or host-publication exception, new egress, or independent
  CP role in DP forwarding is introduced.
- **Gated:** spec-derived startup regressions against effective production configuration,
  address/override/family matrix, calibrated actual-socket observation, unchanged
  authenticated UDS and token/lifecycle controls, driver verification and the ordinary
  independent review gate.
- **Residue:** dev/test defaults and mocked configuration do not prove production
  addresses; a final socket snapshot can miss an early invalid bind; a localhost HTTP
  success also occurs for wildcard listeners. Acceptance requires production-package
  startup ordering evidence plus real namespace observations and positive controls.
  Measured guest/kernel/architecture scope does not establish all release platforms.

## Acceptance

1. Ground the full CPB-M2 report, current constitution and foundation contract, then
   record the high-complexity outline and Constitution Check. Observe the baseline
   packaged CP's actual TCP listeners in its own network namespace, recording baseline,
   package/image/source/configuration identities, process identity and effective family
   configuration. Inspect IPv4 and IPv6 explicitly. A closed host port or successful
   localhost request is insufficient evidence of the bound address. Do not label
   historical source/bytecode analysis as a freshly executed listener observation.
2. Before production edits, add a named `HttpListenerBoundaryTest` (or equivalently
   named focused test in the selected module) and a production-startup/socket probe that
   demonstrate the missing boundary on the baseline. At least one red must be behavioral:
   effective wildcard startup or forbidden listener activation, with a functioning
   positive control, not a missing new class/property or broken fixture. Preserve the
   pre-fix source/test snapshot, command and result using `scripts/test-first-evidence.py`.
3. Choose and document one grounded conforming mechanism: disable/remove unused HTTP
   with an enforced invariant preventing unsupported re-enablement, or retain the finite
   health endpoint with actual loopback enforcement and refusal of wildcard/nonconforming
   effective addresses. A default `quarkus.http.host` or `host-enabled` property alone
   does not meet this acceptance. Ground the exact pinned framework's configuration and
   lifecycle ordering; prove the enforcement runs before the relevant bind/listen path.
   A guard only after Quarkus startup, or a later shutdown of an invalid socket, is not
   refusal before exposure. Removing HTTP must preserve the CP process and its management
   services; retaining HTTP must preserve its finite bodyless health-only contract.
4. Exercise relevant production configuration precedence and activation paths: packaged
   defaults, environment, JVM system properties, supported external config files/locations
   and profile selection, plus conflicting inputs where precedence matters. Inventory
   main HTTP, HTTPS, any framework management HTTP listener and optional HTTP domain socket
   so a second transport cannot bypass the selected invariant. Refuse unsupported activation
   or prove the reviewed production artifact cannot activate it. Exercise wildcard IPv4
   `0.0.0.0`, wildcard IPv6 `::`, non-loopback values, unsupported address families, the
   chosen allowed configuration, normal startup, and restart with a forbidden override.
   Test `::1` positively only if explicitly supported; otherwise establish refusal or
   absence of that family. Preserve no independent CP network egress; address handling
   must not add external DNS resolution. Injected invalid configuration must fail for the
   intended boundary reason, not merely a missing DB/key or unrelated boot failure.
5. Calibrate the probe independently: fixtures/controls include distinct IPv4 loopback,
   IPv4 wildcard, IPv6 loopback and IPv6 wildcard addresses, where supported, plus a
   transient invalid-listener/startup falsifier. Failure to inspect a process/namespace,
   an unavailable family, an empty command result, or a premature CP exit cannot be counted
   as a clean absence. Combine pinned startup-order evidence with a discriminating
   production-startup observation; do not claim polling alone proves no transient bind.
   An intentionally unguarded/default-only mutant must fail the same boundary predicate.
6. Preserve authenticated `control.sock`/`dp.sock` management, successful token generation
   delivery/acknowledgement and observer lifecycle delivery. Supported CP startup/restart
   and observer unavailability still obey their existing contracts. Demonstrate real
   authenticated DP admission and destination-byte forwarding with CP stopped; no CP health
   dependency, route-binding change or Direct fallback is introduced. Keep CP `network_mode:
   none`, existing mount/capability boundaries and diagnostic/health-history suppression.
   Do not widen network, engine, host or Tor-control privileges for this repair.
7. Capture fresh final-candidate evidence in a disposable guest using the saved live-VM
   procedure: actual production identity and namespace, all TCP listener addresses and
   families, selected allowed behavior, override/startup/restart refusals, and Acceptance 6
   positive controls. Record exact image/package/source/config/harness identities, kernel,
   architecture and container runtime, commands, actual outcomes and rerun counts. Required
   unavailable checks remain NOT RUN/SKIP and do not close acceptance. Preserve prior raw
   evidence as historical; never relabel an older image run to changed source. This is
   focused T204 evidence, not T155's integrated real-hour/TLS foundation closure.
8. Reconcile endpoint javadoc, applicable production configuration/deployment comments,
   tests, foundation-boundaries and feature spec/plan/research with the selected mechanism.
   Update directly affected architecture and CP README statements if they would become
   false. Coordinate T190 Acceptance 6 by recording the HealthEndpoint wording as absorbed
   by T204, preserving T190's other work and history. Draft exact reserved THREAT-MODEL,
   quickstart or other user-facing wording and obtain independent evaluation followed by
   maintainer approval before applying it. Approval of this scope does not approve future
   exact prose. No constitutional exception or SECURITY-DECISIONS risk acceptance is included.
9. Capture identical-command green with `scripts/test-first-evidence.py`, bound to the
   final implementation; driver verification and `scripts/review-task.sh` must pass against
   the final candidate. Record ordinary review identities/rounds and evidence limits in
   the normal completion follow-up, plus the Constitution VIII release impact assessment.
   Return a precise evidence handoff to T155. Do not mark T155, other CP/browser findings,
   cumulative milestone review, or external human release review complete.

## Grounded files budget: 34 paths

This inventory bounds the direct repair and foreseeable own-change orphans. Paths marked
new are proposed locations; select the smallest coherent set after mechanism grounding.
The two potential guard locations are alternatives, not a requirement to duplicate logic.
There is no directory exemption and no instruction to touch every listed file.

1. `specs/001-tor-route/tickets/T204-enforce-control-plane-http-listener-boundary.md`.
2. `specs/001-tor-route/STATUS.md`.
3. `specs/001-tor-route/evidence/T204-tests-first.json` (new).
4. `specs/001-tor-route/evidence/T204-live-results.json` (new, sanitized closure).
5. `control-plane/runtime/src/main/resources/application.properties` (production config).
6. `control-plane/runtime/src/main/java/app/zcat/stargate/runtime/StargateControlPlane.java`
   (startup integration/documentation if needed).
7. `control-plane/runtime/src/main/java/app/zcat/stargate/runtime/HttpListenerBoundary.java`
   (new potential guard location).
8. `control-plane/runtime/src/test/java/app/zcat/stargate/runtime/HttpListenerBoundaryTest.java`
   (new production configuration/startup regression).
9. `control-plane/runtime/src/test/java/app/zcat/stargate/runtime/StargateControlPlaneTest.java`
   (boot/UDS fixture or direct own-change regression if affected).
10. `control-plane/runtime/pom.xml` (test/package integration or removal wiring if required).
11. `control-plane/ui/src/main/java/app/zcat/stargate/ui/HealthEndpoint.java`.
12. `control-plane/ui/src/test/java/app/zcat/stargate/ui/HealthEndpointTest.java`.
13. `control-plane/ui/src/main/java/app/zcat/stargate/ui/HttpListenerBoundary.java`
    (new alternative guard location alongside existing HTTP substrate).
14. `control-plane/ui/pom.xml` (endpoint/module wiring and directly affected contract text).
15. `control-plane/entrypoint.sh` (only if chosen invariant requires launch integration).
16. `control-plane/Dockerfile` (actual package/launch or directly affected comments).
17. `compose/docker-compose.local.yml` (direct CP topology/configuration contract).
18. `tests/contract/compose/cp_listener_test.sh` (new normal-package boundary entrypoint).
19. `tests/contract/compose/local_compose_test.sh` (rendered effective topology regression).
20. `tests/contract/compose/operational_logs_test.sh` (launcher fixture only if changed).
21. `tests/live-e2e/local-topology/cp_listener.py` (new namespace/startup probe).
22. `tests/live-e2e/local-topology/test_cp_listener.py` (new discriminating probe controls).
23. `tests/live-e2e/local-topology/run.py` (focused probe integration if needed).
24. `tests/live-e2e/local-topology/README.md` (procedure, required evidence and limits).
25. `specs/001-tor-route/contracts/foundation-boundaries.md`.
26. `specs/001-tor-route/spec.md` (existing endpoint assumption).
27. `specs/001-tor-route/plan.md` (existing endpoint/dependency statements).
28. `specs/001-tor-route/research.md` (supersede stale healthcheck decision locally).
29. `specs/000-architecture/spec.md` (only affected CP listener/topology statements).
30. `THREAT-MODEL.md` (exact approved listener-boundary wording).
31. `control-plane/README.md` (exact approved user-facing correction if changed).
32. `specs/001-tor-route/quickstart.md` (only if affected; exact wording approval).
33. `scripts/subcommands/init` (only a necessary health/startup own-change orphan).
34. `specs/001-tor-route/tickets/T190-control-plane-browser-redteam-minors.md`
    (record endpoint-javadoc item absorbed, no other scope/lifecycle changes).

The preceding approved filing batch owns T155/T078/T190 dependency edges, not hidden
implementation edits. Done/scorecard bookkeeping follows the normal docs completion commit.
If a different directly necessary test/guard path is selected, record the grounded substitution
and count it; the existing budget pregrant governs genuine in-scope additions. No dependency
version update or new library is assumed by this inventory.

## Out-of-scope

T155's preserved candidate, resumption probe, full GetStatus-hour evidence and integrated
closure; extension hardening state/T117; DNS capture integrity; T190's other findings;
T200/T201; T202 host-direct runner; new admin/UI/REST APIs; LAN/VPS implementation; new routes;
DP routing/auth production changes; broad logging or build-system refactoring; new runtime
internet access; constitutional amendments, accepted-risk entries, release approval or push.

Existing tests named in the budget may be updated only to reflect the chosen actual CP HTTP
mechanism or an own-change fixture dependency: `HealthEndpointTest` must retain its bodyless
GET-only/no-other-route assertions if HTTP is retained, or be replaced by discriminating
absence/re-enablement tests if removed; runtime boot tests retain UDS/auth/lifecycle assertions;
Compose and operational-log fixtures retain their capability, history and silence boundaries.
Do not weaken a test merely to clear verification. Historical T040/T041 completion claims and
past evidence are not rewritten. New Majors, reserved wording, unresolved policy and ordinary
round-cap/ESCALATE conditions retain the orchestrator's stop rules.
