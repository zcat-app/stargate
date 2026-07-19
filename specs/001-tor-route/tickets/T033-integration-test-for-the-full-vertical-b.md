---
id: T033
title: 'Integration test for the full vertical: bring up `compose/docker-compo'
status: done
created: 2026-07-04
last_updated: 2026-07-11
source: tasks.md#T033
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - spec.md §"User Story 1 - First-time onion service load"
  - spec.md §FR-005
  - spec.md §FR-007
  - contracts/socks5-auth.md §"Username/password sub-negotiation"
  - contracts/torrc.md §"Rendered file" (ControlPort + CookieAuthentication)
decision_refs: []
reviews: { round: 1, date: 2026-07-11, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-07-11
  verdict: PASS
---

# T033: Integration test for the full vertical: bring up `compose/docker-compo

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Integration test for the full vertical: bring up `compose/docker-compose.local.yml`; load `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion` via the data plane's port 8881 (driven from a Go HTTP client through SOCKS5h); assert page bytes received and Tor sidecar's circuit-status reports an established circuit — `tests/integration/onion_load_test.go`.

## Analysis

**Required** — `privacy_critical: true`. Property map per
`docs/process/analysis.md`.

### Goal restated for grounding

Bring up the full local-profile stack (`compose/docker-compose.local.yml`,
all four services), wait for Tor to bootstrap, then issue an HTTPS GET to
the spec's reference onion (`duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`,
spec.md §"User Story 1") via a Go HTTP client driving SOCKS5h through
the data plane's loopback port 8881 (UNAME = first-party domain,
PASSWD = bearer token per contracts/socks5-auth.md). Assert (a) the page
returns HTTP 200 with a non-empty body and (b) the Tor sidecar's
`GETINFO circuit-status` reports ≥1 BUILT circuit. This is the US1 MVP
gate — the single test that proves the full vertical works end-to-end.

### Must hold

- The request traverses the full vertical: Go HTTP client → SOCKS5h
  (`127.0.0.1:8881`) → data plane → Tor sidecar (`tor:9050`) → Tor
  network → onion service. No short-circuit, no direct dial.
- SOCKS5h semantics: the `.onion` hostname is passed to the SOCKS5 proxy
  as `ATYP=0x03 DOMAIN` (not resolved locally) — FR-007, Principle III.
  `golang.org/x/net/proxy.SOCKS5` does this by default for domain-name
  targets (confirmed by `fake_socks5_tor_test.go`'s domain dial path).
- The SOCKS5 PASSWD carries the bearer token and UNAME carries the
  first-party domain (the onion) — contracts/socks5-auth.md
  §"Username/password sub-negotiation". Reversed mapping would break
  both auth (token in UNAME = ignored) and stream isolation
  (first-party in PASSWD = no IsolateSOCKSAuth key).
- The HTTP response body is non-empty — page bytes were received through
  the full path (not a cached, empty, or error response).
- `GETINFO circuit-status` over the cookie-authenticated control port
  reports ≥1 BUILT circuit — Tor established a usable circuit to serve
  the request.
- The control-port exchange uses cookie auth (never null auth) — mirrors
  T032 and the Dockerfile HEALTHCHECK; the cookie is located via `find`
  (T087: effective DataDirectory is `/var/lib/tor/.tor`, not
  `/var/lib/tor`).
- The test self-skips when prerequisites are absent (test-first per
  Principle VII — the test is the target T047/T050/CP land against).

### Gated (no standing human vigilance needed)

- T015 `local_compose_test.sh` gates the compose file's structural
  contract (port bindings, volumes, UIDs, proxy lockdown) at PR cadence.
- T019b `TestTorPortExposure` gates FR-012 (Tor ports not host-published)
  at runtime.
- T029/T030/T031 gate the rendered torrc's byte-shape and invariants;
  T032 gates the live-sidecar load of the isolation flags.
- verify.sh license-header gate gates SPDX on the new file; `go vet` +
  `gofmt` gate the syntactic surface (when the tests/integration module
  is built). verify.sh does NOT run `tests/integration/` Go tests (Gate
  2 only runs `data-plane/`), so T033 is a release-tag-cadence manual
  gate, not a PR gate.

### Residue

- **Real Tor network + reference onion availability.** The test depends
  on the live Tor network being reachable and the DuckDuckGo onion
  service being up. A partition or onion-service downtime causes failure
  for non-contract reasons. Gated by `STARGATE_RUN_NETWORK_TESTS=1`
  (release-tag opt-in; same cadence as T034a/T034f/T070a). Environmental,
  not a contract gap.
- **Bearer token supplied by the release-run operator.** The test cannot
  self-provision a valid token without the CP's token-management surface
  (T035/T038). `STARGATE_TEST_TOKEN` carries it; a wrong/expired token
  yields auth failure (not a false green). When T035/T038 land, a fixture
  may replace the env var — left to the implementation landing.
- **Control-port exchange via `docker compose exec tor` (nc + coreutils
  + find).** Same coupling as T032 (tor image ships `netcat-openbsd` +
  coreutils); T062 (Phase 4) will land a Go-side cookie client that may
  refactor both. The `find` for the cookie path is the T087 workaround —
  robust to any DataDirectory location.
- **Packet-level DNS-leak and egress-consensus assertions.** Out of scope
  here — T034 (DNS leak, PR-cadence) and T034f (egress consensus,
  release-tag) gate those properties separately via gopacket capture.
  T033 asserts the page-load property only.

### Why bring up the full stack (not seed volumes like T032)

T032 isolates the Tor-side torrc load by seeding the config volume
directly (the CP isn't its concern). T033 is the FULL VERTICAL test —
its contract is "the whole stack works together". Seeding any volume
would short-circuit the path under test. The test brings up all four
services and verifies the integrated path: CP renders torrc → Tor loads
it → DP routes `8881→tor:9050` → onion loads. A failure anywhere in that
chain is a T033 failure, which is the point.

## Acceptance

**File**: `tests/integration/onion_load_test.go` (package `integration`,
same module as `fake_socks5_tor.go`).

**Named test**: `TestOnionLoad`:

- Brings up the full local-profile stack via `docker compose -p
  stargate-t033-test -f compose/docker-compose.local.yml --env-file
  compose/env/local.env.example up -d --build` (all four services).
- Polls Tor bootstrap to `PROGRESS=100` via `docker compose exec tor`
  + cookie-authenticated `GETINFO status/bootstrap-phase` (same
  nc-based exchange as T032 + the Dockerfile HEALTHCHECK; cookie located
  via `find /var/lib/tor -name control_auth_cookie` per T087). 5-minute
  deadline.
- Issues `GET https://<reference-onion>/` via a Go `http.Client` whose
  transport dials SOCKS5h through `127.0.0.1:8881` with
  `Auth{User: <reference-onion>, Password: <STARGATE_TEST_TOKEN>}`
  (UNAME = first-party domain, PASSWD = bearer token per
  contracts/socks5-auth.md). 120 s per-request timeout; 60 s retry
  window to absorb `routeEnableMask[TOR]` propagation after the first
  HEALTHY event.
- Asserts (a) `resp.StatusCode == 200`; (b) `len(body) > 0` (page bytes
  received through the full vertical).
- Queries `GETINFO circuit-status` via `docker compose exec tor`; asserts
  ≥1 response line containing `BUILT` (established circuit).

**Runnable command** (release-tag cadence; not in verify.sh — needs real
Tor network + operator-supplied token):

```
STARGATE_RUN_NETWORK_TESTS=1 STARGATE_TEST_TOKEN=<bearer> \
  go test -run TestOnionLoad -v -timeout 15m ./tests/integration/
```

**Self-skip conditions**: docker CLI absent or daemon unreachable;
`data-plane/cmd/stargate-proxy/main.go` absent (T050 not landed);
`data-plane/internal/forward/tor.go` absent (T047 not landed); no
`.java` sources under `control-plane/` (CP not buildable → cannot render
torrc); `STARGATE_RUN_NETWORK_TESTS` unset (release-tag opt-in);
`STARGATE_TEST_TOKEN` unset (no bearer token to authenticate with).

**Conventions reused from T019b/T032**: `composeProject` namespacing;
`findRepoRoot` via `runtime.Caller`; `t.Cleanup` → `docker compose down
--volumes --remove-orphans` registered BEFORE the compose-up call;
cookie-authenticated control-port exchange via `docker compose exec -T`.

## Out-of-scope

- DNS-leak packet capture (T034 — PR-cadence gopacket gate; SC-003
  hand-driven measurement is T034a).
- Egress-consensus packet capture (T034f — release-tag).
- Circuit isolation / stream-isolation assertions (T059–T061, US2).
- Error-template assertions on sidecar failure (T070, US3).
- Cold-start snapshot survival (T020a — separate contract test).
- The control-plane token-management surface (T035/T038) — the test
  consumes a token via env var; provisioning one is the operator's job
  at release-tag time.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
