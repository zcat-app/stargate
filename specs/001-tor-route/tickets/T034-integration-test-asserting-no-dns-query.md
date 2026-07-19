---
id: T034
title: 'Integration test asserting no DNS query for any `*.onion` name appears'
status: in-review
created: 2026-07-04
last_updated: 2026-07-19
source: tasks.md#T034
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"FR-003"   # proxyDNS:true / SOCKS5h (no local resolution)
  - specs/001-tor-route/spec.md §"FR-007"   # data plane forwards via SOCKS5h, MUST NOT resolve locally
  - specs/001-tor-route/spec.md §"SC-003"   # zero DNS queries for *.onion during session; T034 is the per-PR gopacket version
decision_refs: []
constitution_refs:
  - "III: No outbound except routed request"
  - "VII: Tests-first for privacy-critical paths"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T034: Integration test asserting no DNS query for any `*.onion` name appears

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Integration test asserting no DNS query for any `*.onion` name appears on `lo` or egress NIC for the duration of a 60-second Go-driven routed session — `tests/integration/dns_leak_test.go`. Uses `gopacket` to capture both interfaces; fails on any A/AAAA/MX containing `.onion`. This is a fast PR-time regression gate on the SOCKS5h + `proxyDNS:true` mechanism (FR-003, FR-007); the spec-level SC-003 measurement is T034a.

## Analysis

Required — `privacy_critical: true`. Property map grounded in the cited spec
sections and the on-disk test infrastructure.

- **Must hold:**
  - The file `tests/integration/dns_leak_test.go` exists and is compile-clean
    under `go vet -tags docker live release` (Principle VII — test-first; the
    go-workspace gate compile-checks tagged files even when they are excluded
    from the hermetic test run, T076 §Acceptance #4).
  - The test carries `//go:build docker && linux` so it runs in the named
    Docker PR job (where it has CAP_NET_RAW for `gopacket/afpacket` capture)
    and the hermetic PR gate compile-checks it without executing it (T076
    §"CADENCE SEPARATION"). The `linux` constraint is required because
    `gopacket/afpacket` uses AF_PACKET sockets (Linux-only); without it,
    `go vet -tags docker live release` on a non-Linux dev host would fail
    to compile the afpacket import, breaking the cross-platform green gate.
  - The test self-skips until `data-plane/internal/forward/tor.go` (T047) and
    `data-plane/cmd/stargate-proxy/main.go` (T050) land — the test-first
    pattern from T033: the test is the target the implementation lands
    against, not a downstream consumer.
  - When prerequisites are met, the test captures DNS packets on `lo` AND on
    the egress NIC for the duration of a Go-driven routed session against the
    synthetic SOCKS5 backend (`fake_socks5_tor.go` AcceptAndRelay) and FAILs
    on the first DNS packet whose A/AAAA/MX query name or response name
    contains `.onion` (FR-003, FR-007, Principle III).
  - The test does NOT itself issue any DNS query for a `.onion` name (would
    be a false positive); the routed session drives the data plane via
    SOCKS5h DOMAIN framing (ATYP=0x03) so the only place a `.onion` DNS
    packet could originate is a buggy data plane that resolves locally.
  - The test fails fast: on the first matching DNS packet, it stops the
    capture and reports the leak rather than running the full session window.

- **Gated:**
  - `go vet -tags docker live release` (run by
    `scripts/go-workspace-gate.py` via verify.sh Gate 2) compile-checks the
    tagged test file — a syntax/type regression fails the hermetic PR gate.
  - The go-workspace gate's JSON SKIP accounting (T076 §Acceptance #2) means
    a self-skipping test is reported `SKIP` — never masquerading as `PASS`.
  - `scripts/check-license-headers.sh` gates the SPDX header on the new file.
  - The existing synthetic SOCKS5 backend (`fake_socks5_tor.go`) is reused —
    no new fake infrastructure needed.

- **Residue:**
  - The actual packet-capture + DNS-leak detection path cannot be exercised
    in this environment (T047/T050 not landed; gopacket capture requires
    CAP_NET_RAW). The test's *runtime* correctness is established when
    T047/T050 land and the Docker PR job runs it. Cannot be promoted to
    gated here — the residue is structural (test-first authored before the
    implementation it gates, per Principle VII).
  - The 60-second session window (per task body, mirroring SC-003) cannot
    catch leaks rarer than once per session. Cannot be promoted — SC-003
    pins the canonical measurement at 10 minutes (release-cadence T034a);
    T034 implements the per-PR assertion at the shorter window the task body
    specifies. Sub-session-cadence leaks are release-cadence residue.
  - `gopacket`'s DNS layer parser is trusted to identify `.onion`-bearing
    queries correctly. Out of scope to test the parser itself; correctness
    is upstream's responsibility.
  - The `STARGATE_TEST_TOKEN_PLAINTEXT` + `STARGATE_TOR_SOCKS5` env-var
    contract this test assumes is owned by T050 (shared with T079a).
    T050 MUST land with these env vars honoured only under a test harness
    (gated by a build tag, a `STARGATE_TEST_ONLY=1` sentinel, or compiled
    out of release builds). Honouring them unconditionally in production
    would let any attacker who controls DP env vars inject a known
    plaintext token and bypass FR-006's HMAC-verifier-list auth — a
    Principle III violation. This is a contract surface T050 must get
    right; T034 inherits the assumption. Surfaced by stargate-redteam.

## Acceptance

1. Named test `TestDNSLeak` exists in `tests/integration/dns_leak_test.go`
   with a `//go:build docker && linux` build tag (Principle VII test-first;
   tagged for the named Docker PR job per T076 §Acceptance #4 — packet
   capture needs CAP_NET_RAW; `linux` required because
   `gopacket/afpacket` uses AF_PACKET sockets).
2. `cd tests/integration && go vet -tags docker live release` exits 0 —
   the hermetic PR gate's compile-check passes (T076 §Acceptance #5).
3. `cd tests/integration && go test -tags docker -run TestDNSLeak` self-skips
   with a message naming the missing prerequisite (T047's
   `data-plane/internal/forward/tor.go` or T050's
   `data-plane/cmd/stargate-proxy/main.go`) — the test-first pattern from
   T033; the test is the target the implementation lands against.
4. When prerequisites land (post-T047/T050), the test brings up the
   synthetic SOCKS5 backend (`fake_socks5_tor.go` AcceptAndRelay), starts a
   `gopacket/afpacket` capture on `lo` AND on the egress NIC, drives a
   60-second routed session of `.onion` CONNECTs through the data plane
   (ATYP=0x03 DOMAIN — SOCKS5h, no client-side resolution), and FAILs on the
   first DNS packet whose query name or response name matches `*.onion`
   (FR-003, FR-007, Principle III).
5. `scripts/verify.sh` is GREEN — the new file is compile-checked under
   `go vet -tags docker live release`, the test self-skips under the
   hermetic PR run (accounted `SKIP[docker]` per T076), and no other gate
   regresses.

## Out-of-scope

- **T034a** — release-cadence SC-003 Wireshark/tshark measurement against
  a real Mullvad Browser session (separate ticket).
- **T034f** — egress-consensus packet capture against live Tor consensus
  (separate ticket).
- The extension's runtime `proxyDNS:true` assertion — exercised by the
  extension test suite (T034b), not the integration test.
- Any change to the data plane — T047 (forward/tor.go) and T050
  (cmd/stargate-proxy/main.go) land the implementation; T034 is test-only.
- Live network verification — this test uses the synthetic SOCKS5 backend
  (`fake_socks5_tor.go`), not the real Tor network.
- A guarantee of catching arbitrarily rare DNS leaks — the 60s window
  matches SC-003 / the task body; sub-window-cadence leaks are
  release-cadence residue owned by T034a.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
