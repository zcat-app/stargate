---
id: T189
title: 'Resolve surviving transport-area redteam minors'
status: pending
created: 2026-09-29
last_updated: 2026-10-05
source: "reviews/redteam-20260929-694dbd8.md (area 1 minors that survived falsification); items 6-7 and the item-4 alert addition from the T155 attempt-4 redteam (maintainer approved 2026-10-03); the item-4 tor:9050 and torrc.md additions and item 8 from the T155 r5 cumulative redteam and T208's left-open note (falsified 2026-10-05), maintainer approved 2026-10-05 (torrc.md under the maintainer's delegation)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 16  # raised 10 -> 15 for the T155 attempt-4 additions, each path named by its item:
                  # tests/live-e2e/local-topology/connect_refusal.py + test_connect_refusal.py (item 6);
                  # specs/001-tor-route/contracts/wire-auth.md (item 4 alert); specs/001-tor-route/data-model.md + data-plane/internal/auth/token.go (item 7)
                  # raised 15 -> 16 (maintainer-approved 2026-10-05): tests/contract/internal/dpharness/dpharness.go (item 4 tor:9050);
                  # socks5-auth.md, torrc.md and THREAT-MODEL.md are already counted by item 4.
                  # The earlier 15 was not re-inventoried against items 1-7; the T189 developer checks it at START.
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "I: Dumb Router (NON-NEGOTIABLE)"
  - "III: Privacy-Preserving by Construction"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/socks5-auth.md
  - specs/001-tor-route/spec.md#FR-002
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T189: Resolve surviving transport-area redteam minors

## Context

The 2026-09-29 cumulative redteam (snapshot 694dbd8) was followed by a
falsification pass. Only findings that survived it, with their corrected
claims, are listed here. Falsified or accepted items (half-close, clock jump,
errortpl, username shape, loadedAt, single-request byte count, T061 threshold,
IPv6 loopback) are recorded in the review report and are not in scope; item 7 covers
only the accuracy of the `loadedAt` documentation, not the accepted field itself.

## Analysis

- Must hold: each item below is fixed with a discriminating regression, or its
  normative text is corrected so no claim exceeds what is enforced.
- Gated: `scripts/verify.sh`; mutation evidence per item where a test is added.
- Residue: none beyond what each item states.

## Acceptance

1. Upstream method selection (defence in depth): the DP offers Tor only RFC 1929
   username/password and treats any other selected method as ROUTE_REFUSED with
   zero forwarded bytes. The regression uses a stub that selects no-auth whenever
   offered. Optionally forbid `PreferSOCKSNoAuth` in the torrc invariants.
2. Pre-auth flood: bound concurrent pre-auth connections (sized against the
   512m memory limit) and do not exit on temporary Accept errors; test both.
3. Log tests: pin that the DP's fds 1/2 are `/dev/null` (e.g. `/proc/<pid>/fd`)
   and point the no-per-request-log assertions at the retained channels
   (state volume, /tmp, RPC payloads) with a positive control.
4. Stale username wording: correct `contracts/socks5-auth.md:86-89`,
   `THREAT-MODEL.md:1098-1101` (since moved to about `:1294-1297`), `contracts/torrc.md:52`,
   `spec.md:142` and the US2 acceptance scenario at `spec.md:170` to the opaque `sg1:` HMAC
   username. Also (T155 attempt 4, Info): `contracts/wire-auth.md` §3.3 (about `:202`) and
   `THREAT-MODEL.md` about `:1957` say a peer-pin mismatch aborts with `alert: unknown ca`;
   the Go DP sends `bad_certificate` in both roles (falsifier RAN a TLS 1.3 rejecting
   `VerifyConnection`). Name the alert correctly or drop its name; a grep of specs and
   THREAT-MODEL finds no "unknown ca" outside history notes. THREAT-MODEL wording needs
   maintainer approval.
   Also (T155 r5 cumulative redteam, area 1 i5, Info, falsified 2026-10-05; maintainer
   approved filing 2026-10-05): `contracts/socks5-auth.md` §Deadlines row 1 says "Open TCP
   to `tor:9050`", and `tests/contract/internal/dpharness/dpharness.go` comments name
   `tor:9050` as the production default; the DP dials Tor's Unix socket
   (`unix:///run/stargate-tor/tor-socks.sock`). Name the Unix-socket adapter in both. The
   §Deadlines row carries T208's maintainer-approved wording (2026-10-05): change only the
   `tor:9050` phrase, and return the exact replacement for approval before writing it.
   Afterwards `grep -rn "tor:9050" specs/001-tor-route/contracts tests/contract/internal`
   finds nothing outside quoted history.
   Also (T208 orphan recorded at T208's "Left as they are" note; maintainer delegated the
   filing choice 2026-10-05, orchestrator decided): `contracts/torrc.md` §"`invariants_test.go`"
   says the test "Parses the golden and asserts each invariant above individually"; since
   T208 its invariant-14 case also reads the shipped `sidecars/tor/torrc`. Complete the
   sentence. Contract wording needs maintainer approval.
5. Constant-time claim: add a test that fails when the production verifier loop
   exits early (e.g. an internal compare-count hook), or correct
   `socks5-auth.md:137` and the leak_test header to what is actually tested.
6. (T155 attempt 4, area 3 m1) `tests/live-e2e/local-topology/connect_refusal.py` carries its
   verdicts and its disposable-host guard as bare `assert`s, which `python3 -O` /
   `PYTHONOPTIMIZE` removes: a forbidden trace is then accepted and PASS is written. Make every
   verdict and the guard independent of `assert` (or refuse to run under `-O`). Red before
   green: a unit test in `test_connect_refusal.py` that runs the validator under `-O` with a
   forbidden trace must fail before the fix and pass after.
7. (T155 attempt 4, Info) `data-model.md:167` describes the snapshot's `loadedAt` as the
   "current snapshot creation time", and `data-plane/internal/auth/token.go:47-49` as when the
   generation was received. After a CP replay of the same generation, `loadedAt` keeps the last
   authority-change time while the file is rewritten (falsifier RAN). Correct both texts to
   the actual semantics, or drop the field (then with a test that the snapshot holds no
   wall-clock timestamp).
8. (T155 r5 cumulative redteam, area 1 i3, narrowed to Info by falsification 2026-10-05;
   maintainer approved filing 2026-10-05) THREAT-MODEL §5.14 notes the constant-time
   comparison residue but not that authentication-failure latency grows with the number of
   enrolled verifiers, so a same-host process averaging many failed attempts could in
   principle estimate that count (read from the code; unmeasured). Add one residue sentence
   to §5.14. No code change and no new test are claimed. THREAT-MODEL wording needs
   maintainer approval.

## Out-of-scope

Behaviour changes to the sg1 username contract; T079a memory bounds beyond item 2.
