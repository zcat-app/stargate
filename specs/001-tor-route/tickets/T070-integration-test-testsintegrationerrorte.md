---
id: T070
title: "Test integrated SOCKS5 Tor failure response"
status: done
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T070
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T064", "T156"]
parallel: true
files_budget: 4
files_scope:
  - tests/integration/route_down_stack_test.go
  - tests/integration/go.mod
  - specs/001-tor-route/tickets/T070-integration-test-testsintegrationerrorte.md
  - specs/001-tor-route/STATUS.md
out_of_scope:
  - Production data-plane, control-plane, sidecar, Compose, or firewall implementation changes
  - HTTP CONNECT ingress or HTTP error-template behavior on Tor port 8881
  - ROUTE_REFUSED, ROUTE_TIMEOUT, or mid-request Tor-circuit failure coverage owned by other tickets
  - VM creation, Docker pruning, or cleanup of resources outside the unique T070 Compose project
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "I: Dumb Router"
  - "III: Privacy-Preserving by Construction"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md §"User Story 3 — Privacy-safe failure when Tor is down" and FR-006–FR-009'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"'
  - 'specs/001-tor-route/contracts/foundation-boundaries.md §"Deployment and authority"'
  - 'specs/001-tor-route/contracts/error-template.md §"Leak-corpus invariant"'
decision_refs:
  - 'T172 selected acceptance: preserve authenticated SOCKS5 and exact ROUTE_DOWN; no HTTP template ingress'
  - 'T025a shared diagnostics/leak-scan oracle in tests/internal/loginvariants'
reviews: { round: 2, date: 2026-10-09, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T070: Test integrated SOCKS5 Tor failure response

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Integration test `tests/integration/error_template_test.go` — end-to-end version of T065: bring up the stack, stop the Tor sidecar mid-session, request a `.onion` URL through the data plane, capture the full response, run the leak-corpus scan.

## Analysis

- **Must hold:** the actual Local stack admits the test token and reaches the pinned live onion before the negative probe. After only the T070 project's Tor service stops, a fresh authenticated SOCKS5 CONNECT to the controlled synthetic onion returns exactly `05 03 00 01 00 00 00 00 00 00`, then closes at EOF. The full reply and the bounded DP stdout/stderr observed during the request window contain no shared leak-corpus hit and satisfy the T025a diagnostic policy. IPv4 and IPv6 host `STARGATE_DP_OUT` DROP counters do not increase for the failed route request, so no Direct fallback attempt passed the host enforcement point. Teardown removes only the unique project's containers, volumes, and networks.
- **Gated:** the Docker-tagged `TestT070IntegratedRouteDown` verifies the live positive control, authentication, Tor-only stop, raw SOCKS bytes/EOF, confirmed live diagnostics attachment with Docker logging disabled, leak scan, both host counter deltas, and project-scoped cleanup. The host wrapper records the clean firewall/AppArmor baseline before the run and verifies exact restoration afterward.
- **Residue:** this is one live run on the measured host/kernel and one reference onion at the time of the run. The counter result proves no packet hit the measured host owner-rule DROP path in this request window; it does not generalize to other hosts, kernel families, routes, or requests. The live evidence depends on the onion being reachable for the positive control; setup/connectivity failure is a test failure, never a pass for the negative case.
- **Host builder findings:** the failed aggregate Compose build selected Docker's legacy builder because the privileged helper runs as root and did not discover the existing Buildx plugin in Claudia's Docker config. The legacy builder rejects the control-plane Dockerfile's required `COPY --chmod`. A focused aggregate build passed after Compose received an isolated temporary `DOCKER_CONFIG` containing only the existing Buildx plugin, copied from `STARGATE_T070_BUILDX_PLUGIN` and checked against SHA-256 `912118a5a65bf2f13dd7c2e5912857c50f43842bf4ec0f4378bcb28af66aaac3`; the user's Docker config and credentials were not copied or injected into init. The earlier Tor key-fetch observation remains separate: the successful probe kept the test-only `tor.build.network: host` override, so it does not establish behavior on the default BuildKit RUN network. The override remains limited to the exact init `compose up -d --build` call; the canonical Compose file, Dockerfile, key/package checks, image tags, and runtime model remain unchanged.

## Acceptance

1. Add named Docker-tagged test `TestT070IntegratedRouteDown` in
   `tests/integration/route_down_stack_test.go`. It owns a unique Compose
   project and private `local.env`, verifies the project starts empty and the
   rendered Local stack contains exactly the expected services, then invokes
   the real `scripts/stargate init` and seeds/reloads one test token.
2. Before stopping Tor, send a raw authenticated SOCKS5 CONNECT through
   `127.0.0.1:8881` to the spec-pinned live reference onion and require REP
   success. Assert the DP has Docker logging driver `none`, attach a live
   stdout/stderr reader, and fail closed if it cannot attach, exits before the
   request window ends, or exceeds its bounded capture.
3. Snapshot both host `STARGATE_DP_OUT` DROP counters, stop only this project's
   `tor` service, and verify those counters remain unchanged through stop.
   Send a fresh authenticated raw SOCKS5 CONNECT to
   `t070-route-down-controlled-address.onion:443`; require the exact ten-byte
   `05 03 00 01 00 00 00 00 00 00` reply and clean EOF with no trailing bytes.
   Require both DROP counters to remain unchanged during that request.
4. Scan the complete reply and bounded live DP output against the committed
   leak corpus and shared T025a diagnostics policy. On completion, failure, or
   signal, remove only this unique Compose project's containers, volumes, and
   networks; verify none remain. The focused runner also restores and verifies
   its previously clean host AppArmor/firewall baseline.
5. Run only the focused live test with
   `cd tests/integration && go test -tags docker -run '^TestT070IntegratedRouteDown$' -v -timeout 32m`,
   under the bounded host-boundary runner. Do not run Java or the repository-wide
   verification gate for this ticket.

## Out-of-scope

This ticket adds only live integration coverage and the integration module's
reference to the shared T025a scanner. It does not change forwarding behavior,
host-boundary implementation, other route failures, or the HTTP renderer.
T070a owns mid-request circuit loss; T067a/b own request-phase failure details
and counters. No VM, Docker prune, unrelated Compose project, or global
resource cleanup is part of this test.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Run the actual Local stack with Tor stopped and send an authenticated SOCKS5 CONNECT to a controlled onion destination. Assert exact 10-byte `ROUTE_DOWN` reply, EOF, no leak-corpus/log hit and no Direct fallback; use a live Tor/SOCKS positive control. No HTTP template is expected.
