---
id: T189
title: 'Resolve surviving transport-area redteam minors'
status: done
created: 2026-09-29
last_updated: 2026-10-18
source: "reviews/redteam-20260929-694dbd8.md (area 1 minors that survived falsification); items 6-7 and the item-4 alert addition from the T155 attempt-4 redteam (maintainer approved 2026-10-03); the item-4 tor:9050 and torrc.md additions and item 8 from the T155 r5 cumulative redteam and T208's left-open note (falsified 2026-10-05), maintainer approved 2026-10-05 (torrc.md under the maintainer's delegation)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 21  # raised 10 -> 15 for the T155 attempt-4 additions, each path named by its item:
                  # tests/live-e2e/local-topology/connect_refusal.py + test_connect_refusal.py (item 6);
                  # specs/001-tor-route/contracts/wire-auth.md (item 4 alert); specs/001-tor-route/data-model.md + data-plane/internal/auth/token.go (item 7)
                  # raised 15 -> 16 (maintainer-approved 2026-10-05): tests/contract/internal/dpharness/dpharness.go (item 4 tor:9050);
                  # socks5-auth.md, torrc.md and THREAT-MODEL.md are already counted by item 4.
                  # AC2 source-slice reconciliation: 16 -> 20 for data-plane/cmd/stargate-proxy/main.go, data-plane/internal/listener/socks5.go, and new data-plane/internal/listener/serve.go + serve_test.go. Only these four paths are added; lifecycle remains in-progress.
                  # raised 20 -> 21 (2026-10-18): scripts/go-workspace-gate.py gives tests/contract a 12m Go test timeout. The full SC-005 race package exceeded Go's 10m default after two existing 251s route-timeout tests; a test-name reorder cannot change Go's package-wide timeout. This preserves all tests and SC-005's required 60s hold; other modules retain Go's default.
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
reviews: { round: 2, date: 2026-10-18, verdict: ESCALATE }
overrides:
  - date: "2026-10-18"
    by: user
    decision: "Affected-part tests only for T189; omit scripts/verify.sh and unrelated suites."
    reason: "The user explicitly authorized this scoped verification override in .scratch/reports/2026-10-16-fresh-session-finish-tor-prompt.md: affected-part tests only (not full scripts/verify.sh), and equivalent deterministic lifecycle steps with scoped-verification records when the driver hardcodes a conflicting full-suite step. This changes only the pre-review procedure for T189; no acceptance, privacy, or security guarantee is waived. The exact affected RED/GREEN selectors and other acceptance evidence remain recorded."
  - date: "2026-10-18"
    by: user
    decision: "Override round-2 ESCALATE on the full scripts/verify.sh demand; retain the actual ESCALATE review record."
    reason: "The explicit session authorization requires affected-part tests only and forbids rerunning scripts/verify.sh. Both round-2 reviewers found AC1-AC8 met and no code-level finding; the remaining verification objection conflicts with that authorization. The separate Minor last_updated defect is corrected. The scoped results are recorded in evidence/T189-tests-first.json; no full-gate pass is claimed and no acceptance or security guarantee is waived."
aborted_attempts: [{ date: 2026-10-18, round: 2, reason: "review-loop refine restart (run-task --reset)", history: target/runs/T189.review-history }]
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
   Selected AC1 implementation: enforce USERNAME/PASSWORD-only upstream negotiation in `dialUpstream`. The no-auth-preferring stub verifies early refusal with zero forwarded bytes.
2. Pre-auth flood: bound concurrent pre-auth connections (sized against the
   512m memory limit) and do not exit on temporary Accept errors. “Temporary”
   includes a wrapped Accept error whose `Temporary()` is true and `Timeout()`
   is false (for example, resource pressure); retry with bounded backoff that
   honors context cancellation, while returning permanent errors. Tests must
   show a usable connection is handled after such an error and that retries do
   not spin.
3. Retained-channel observations: pin that DP fds 1/2 are `/dev/null` (e.g.
   `/proc/<pid>/fd`) and compare before/after observations around both an
   authentication failure and successful authenticated CONNECT plus opaque
   payload. Observe state volume, the harness-owned private `TMPDIR` subtree,
   one unique exact absolute pathname under `/tmp` outside that subtree, and
   actual captured DP-to-CP WatchEvents payload/metadata. The `/tmp` observer
   must use a child-process positive control that writes a unique marker to the
   exact absolute pathname, plus a clean/absent negative control; it must not
   walk unrelated shared-host `/tmp` files. RPC positive controls must be
   independent payload-only and metadata-only requests through
   `RPCRequestCapture.Record/Snapshot`, never manually constructed captured
   records. Bounded capture-limit errors remain sticky and visible through
   `Snapshot`, and either request-flow assertion fails on such an error rather
   than reusing an earlier snapshot. The successful-flow evidence must include
   an explicitly selected passing execution of
   `TestT189SuccessPathNoPerRequestRetainedChannel`. These observers are
   test-side evidence only: the reviewed gap is coverage/evidence, not an
   observed production leak.
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
   Selected AC5 documentation alternative: correct the contract and test comments to describe their actual coverage. The production full-set comparison requirement remains; these tests do not instrument production verifier visits.
6. (T155 attempt 4, area 3 m1) `tests/live-e2e/local-topology/connect_refusal.py` carries its
   verdicts and its disposable-host guard as bare `assert`s, which `python3 -O` /
   `PYTHONOPTIMIZE` removes: a forbidden trace is then accepted and PASS is written. Make every
   verdict and the guard independent of `assert` (or refuse to run under `-O`). Red before
   green: a unit test in `test_connect_refusal.py` that runs the validator under `-O` with a
   forbidden trace must fail before the fix and pass after.
   Selected implementation: refuse optimized Python at module admission with a fixed explicit exception before imports or validator/live-path execution.
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

## Maintainer disposition — 2026-10-18

The exact round-2 GLM and Astra verdicts remain `ESCALATE`; they are not
relabeled as approvals. Both reports found AC1–AC8 met and no code-level
failure. The remaining gate objection required a full `scripts/verify.sh`
run, which the maintainer explicitly excluded for this session. The ticket
also records the corrected `last_updated` metadata finding. Affected-part
verification was rerun on the current staged T189 source and is recorded in
`evidence/T189-tests-first.json`. The historical full-verification attempt
remains non-green in `target/runs/T189.verify.log`; this disposition does not
claim it passed. The maintainer's explicit override resolves only that
procedural gate, without waiving a privacy or security acceptance criterion.

The round-2 review also identified an inaccurate THREAT-MODEL sentence that
said the production comparison loop was functionally tested. The sentence is
corrected in this T189 scope: the production loop compares every verifier,
while T093 tests cover a reference helper and do not instrument production
visits. The timing residue remains explicit.

## Review refinement record — 2026-10-18

The round-2 GLM and Astra verdicts remain immutable at
`target/runs/T189.review-glm.verdict` (SHA-256
`a5c08d225814bac1f8d3ef2615233f54e850c169ee869f6f739627e153ded637`) and
`target/runs/T189.review-astra.verdict` (SHA-256
`f63fb273b6166e19f13c4d78f0f2df568b6965f10b94db2affefe1154bd5c008`). Their
consumed round counts and prior invalidated history are retained; this
clarification does not waive or relabel any finding. The refinement makes AC2's
temporary-error boundary executable and makes AC3's successful-flow, exact
`/tmp` observation, independent RPC controls, and sticky-error requirements
explicit. The stale auth-log contract row now describes the implemented
fd/retained-channel observer. Evidence records the non-timeout temporary-accept
RED/GREEN, independent RPC-field-control mutation RED/GREEN, and the explicit
successful-authenticated-flow selector/result. No production leak was observed
in either review.
