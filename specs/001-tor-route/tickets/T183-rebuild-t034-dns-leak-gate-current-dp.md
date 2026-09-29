---
id: T183
title: 'Rebuild the T034 DNS-leak gate on the current DP interface'
status: done
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 1 M2, survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 7   # dns_leak_test.go + .gitleaks.toml allowlist prose + this ticket + STATUS.md regen + evidence/T183-tests-first.json (4 -> 5 user-authorized standing rule: fix the .gitleaks.toml description this ticket makes stale, no deferral) + scripts/go-workspace-gate.py + tests/contract/workflow/verify_discovery_test.sh (5 -> 7 maintainer-authorised 2026-09-29, option A, for Astra round-1 finding 1: name skipped tests with their reason in verify output)
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"   # DNS and route failure
  - "VII: Tests-First for Privacy-Critical and Contract Code"   # coverage cannot disappear through skips
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-003
  - specs/001-tor-route/spec.md#FR-007
decision_refs: []
remediates: "T034"
reviews: { round: 1, date: 2026-09-29, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: ["20260929-001-dns-leak-gate-stale"]
clarity_check: {}
---

# T183: Rebuild the T034 DNS-leak gate on the current DP interface

## Context

`tests/integration/dns_leak_test.go` (T034, `status: done`) boots the DP with
`STARGATE_TOR_SOCKS5` and `STARGATE_TEST_TOKEN_PLAINTEXT`. Neither exists in
the DP: `data-plane/cmd/stargate-proxy/main.go` reads `STARGATE_TOR_SOCKS_ADDR`,
requires a `unix://` upstream and loads a pepper from the keys directory.
Falsification (2026-09-29) ran the real DP with the test's environment: it
exits 1 at startup. The test's `CircuitIDs()==0` guard makes it fail rather
than pass vacuously, but no current evidence covers FR-003's "no DNS during a
routed session". The property is defended structurally (no resolver code,
seccomp/Landlock, owner DROP rules, T163 packet evidence); the gate is not.

## Analysis

- Must hold: a routed `.onion`/hostname SOCKS5h session through the real DP
  emits zero DNS packets from the DP, observed on a capture that is proven able
  to see DNS.
- Gated: the rebuilt gate runs in its declared cadence with RUN/PASS, not SKIP.
- Residue: capture scope (loopback/host) is stated; it does not cover the
  browser, which T157/T188 own.

### START analysis (2026-09-29)

Property map:

- Must hold: during a routed SOCKS5h session through the real DP binary
  (production boot path, confinement applied), no DNS packet naming any
  routed target (`.onion` corpus plus hostname targets) appears on `lo` or the
  default-route NIC. Controls: capture started on both interfaces; every
  CONNECT round-trips through the DP to the fake Unix upstream (forwarding
  exercised); a synthetic resolver query from the unconfined test process is
  observed on each captured interface before the zero-leak verdict counts.
- Gated today: nothing. At HEAD the test is `//go:build docker` inside the
  mixed `tests/integration` package, so hermetic `verify.sh` never compiles it
  into the run or names it (the header's "accounts this package SKIP[docker]"
  holds only for all-tagged packages), and under `-tags docker` the DP exits
  at startup. Recorded stale run (probe below, HEAD bd18c95): exit 1,
  `data plane did not listen on 127.0.0.1:8881 within 15s`.
- Residue: browser DNS (T157/T188); DNS over TCP/DoT/DoH from the DP (the
  seccomp filter already denies non-Unix sockets); capture sees only this
  network namespace's `lo` + default-route NIC.

Design (interface grounding, verified on disk):

- Boot the DP exactly as production: `STARGATE_LISTEN_ADDR`,
  `STARGATE_STATE_DIR`, `STARGATE_KEYS_DIR`, `STARGATE_IPC_DIR`,
  `STARGATE_TOR_SOCKS_ADDR=unix://…` (main.go). `tests/integration` cannot
  import `tests/contract/internal/dpharness` (Go internal rule), so the token
  arrives through the production cold-start path instead of ReloadTokens: a
  schema-3 `dp-snapshot.json` (controlclient/snapshot.go) holding the
  HMAC-SHA-256 verifier of a per-run random token under a per-run random
  pepper. No keys → degraded mode, no dp.sock, routing continues (Principle
  II). No production code or environment surface changes.
- Upstream: the existing `fake_socks5_tor.go` `WithUnixSocket` (no adapter).
  Usernames: the T126 `sg1:` partition helper.
- Cadence (acceptance 4): drop the `docker` tag (keep `linux`). The test then
  compiles into every hermetic run and self-skips with an explicit reason when
  it lacks CAP_NET_RAW, so the Go gate counts it as a skip instead of omitting
  it; with CAP_NET_RAW (root container, named docker job) it runs and passes.
- Simulated DP-side query (acceptance 3): `TestDNSLeakDetectsSimulatedDPQuery`
  runs the same harness and verdict with a resolver query for a routed
  hostname injected mid-session and requires the verdict to fail. The
  tests-first red record additionally uses a temporary production mutation
  (confinement skipped + target resolved before forwarding), reverted before
  green.
- Probe (identical red/green command): round 1 used the gitignored
  `target/runs/T183/probe.sh`; round 2 records a self-contained inline
  `bash -c` command in the evidence (Astra round-1 finding 2). It compiles
  `tests/integration` and runs `^TestDNSLeak` as root in a disposable
  container (own netns, resolver pinned to TEST-NET-1 `192.0.2.1`), then runs
  `tests/contract/workflow/verify_discovery_test.sh`. After the refine
  (acceptance 5) the container is the public `debian:trixie-slim` image by
  digest, used as-is; the Go toolchain and module cache are mounted read-only.
- Named skip reporting (acceptance 4; Astra round-1 finding 1, option A
  maintainer-authorised): `scripts/go-workspace-gate.py` prints, under each
  package record, `    test PASS: <pkg>.<Test> (<s>s)` for every top-level
  test that ran and `    test SKIP: <pkg>.<Test> — <reason>` for every skip.
  Indented, so verify.sh's gate-level `^SKIP:` sentinel is not triggered.
  Regression: a skip-with-reason test in the passing `moda` fixture of
  `verify_discovery_test.sh`.
- Orphan: `.gitleaks.toml` describes the fixture token as living in this file
  and reaching the DP via `STARGATE_TEST_TOKEN_PLAINTEXT`; both become false,
  so its description is corrected here (budget 4 → 5).

## Acceptance

1. Rebuild T034 on the current DP interface (e.g. `tests/contract/internal/dpharness`
   with a Unix upstream, seeded pepper and a token delivered through
   `ReloadTokens`, or the Local compose stack). No test-only DP environment
   surface is added to production code.
2. Keep the capture-started and forwarding-exercised guards. Add a positive
   control: a deliberate resolver query from an unconfined helper must appear
   in the same capture before the DP's zero-DNS assertion counts.
3. Red before green: record the current failing run, then the passing run of
   the identical command with `scripts/test-first-evidence.py`. Record that the
   positive control fails the assertion when the DP-side query is simulated.
4. `scripts/verify.sh` reports the gate honestly (RUN/PASS in its cadence, a
   `SKIP:` line otherwise).
5. The tests-first red/green probe runs in a public base image referenced by
   its immutable digest (e.g. `debian:trixie-slim` pinned as
   `debian@sha256:…`), used as-is with no local build. (Refinement authorised
   by the maintainer on 2026-09-29 in response to Astra's round-2 ESCALATE.)

## Out-of-scope

Production DP behaviour changes; browser-side DNS (T188/T157); IPv6 routed egress.

## Implementation notes

Refine (2026-09-29): Astra ESCALATEd round 2 because the probe ran the
unidentified local image `t165-qemu11:local`. The maintainer chose refine and
authorised acceptance 5; the round state was reset and the ticket re-entered
in-progress with its staged candidate kept (restarting from `pending` would
require discarding the candidate, since START refuses a dirty tree).

Evidence (`specs/001-tor-route/evidence/T183-tests-first.json`, re-recorded
after the refine with the inline probe command; root container with its own
netns running the public
`debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a`
(`debian:trixie-slim`) as-is, plus the verify_discovery contract test):

- Stale gate at HEAD bd18c95 (acceptance 3, "current failing run"), same
  probe before any edit: exit 1 after 38.9 s, `data plane did not listen on
  127.0.0.1:8881 within 15s` — the DP exits at boot on the retired env
  surface. This is an interface failure, not a property falsifier, so the
  recorded red uses the rebuilt gate against a mutated DP instead.
- Red: rebuilt test staged with a temporary production mutation (confinement
  skipped in `main.go`, `net.LookupHost` of the target in
  `forward/tor.go dialUpstream`), both preserved in the red patch and
  reverted before green. `TestDNSLeak` fails with `DNS LEAK DETECTED` and 24
  A/AAAA queries for the hostname targets on `eth0` → 192.0.2.1:53. The new
  verify_discovery case fails in the same red run (gate unchanged: no
  `test SKIP:`/`test PASS:` lines).
- Green: identical command, unmutated DP and the gate change:
  `TestDNSLeak` PASS (60 CONNECTs, 17 partitions, controls seen on lo +
  eth0, zero routed-target DNS) and verify_discovery PASS.
- Simulated DP-side query (acceptance 3): `TestDNSLeakDetectsSimulatedDPQuery`
  passes in both records — the verdict fails with the injected
  `t183-hostname-probe.example.org` query while every other guard holds.
- Unprivileged run (hermetic gate): both tests skip with
  `SKIP: DNS-leak gate needs CAP_NET_RAW …`; verify.log names each as
  `test SKIP: …integration.TestDNSLeak — SKIP: DNS-leak gate needs …`.
- Harness fix found live: gopacket's default poll(2) timeout is infinite, so
  capture on a quiet `lo` never observed cancellation; `OptPollTimeout` bounds it.
