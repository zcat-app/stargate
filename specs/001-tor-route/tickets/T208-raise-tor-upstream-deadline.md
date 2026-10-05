---
id: "T208"
title: "Raise the Tor upstream deadline; align the onion-load gate"
status: pending
created: "2026-10-05"
last_updated: "2026-10-05"
source: "T155 TestOnionLoad diagnosis, 2026-10-04; maintainer chose option A (fix the contract deadline and align the tests)"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T033", "T047", "T182", "T187", "T205"]
parallel: false
files_budget: 23
privacy_critical: true
tests_first: []
complexity: medium
risk: medium
round_cap: 2
remediates: "T047"
spec_refs:
  - "specs/001-tor-route/contracts/socks5-auth.md §SOCKS5 request-phase failures (post-auth) and §Deadlines"
  - "specs/001-tor-route/contracts/torrc.md §Invariants"
  - "specs/001-tor-route/spec.md §User Story 1"
  - "specs/001-tor-route/data-model.md §1.8 delivery status row (T187)"
  - "THREAT-MODEL.md §5.10"
constitution_refs:
  - "I: Dumb Router — forwarding stays a byte pipe with no per-request records"
  - "III: route failure replies carry no destination metadata"
  - "V: honest contract rationale; threat model updated in the same reviewed change"
  - "VII/VIII: tests-first, independent review and exact-candidate evidence"
decision_refs:
  - "2026-10-04 maintainer: \"ok go with A, draft the ticket and wording\" (fix the contract deadline and align the tests)"
  - "2026-10-05 maintainer: \"ok 250s, wording approved\" (value 250 s; socks5-auth §Deadlines, torrc invariant 14 and THREAT-MODEL §5.10 wording as drafted in .scratch/tmp/T208/T208-draft.md Part 2)"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T208: Raise the Tor upstream deadline; align the onion-load gate

## Context

`contracts/socks5-auth.md` §Deadlines sets the data plane's upstream dial-and-handshake
deadline at 30 s, on the stated expectation that an onion connect takes 5–15 s typically
and 20–25 s at worst. T047 wired it as `upstreamDialTimeout` in
`data-plane/internal/forward/tor.go`; `TestProductionDialDeadlineIsThirtySeconds` pins it.

Measurements taken under T155 on 2026-10-04, with the shipped Tor 0.4.9.13 sidecar image
and torrc, in the emulated guest and at native speed on the outer host, do not support
that expectation. Raw files (gitignored, with `SHA256SUMS.txt`):
`/home/claudia/stargate/.scratch/tmp/T155/onion-rootcause/run-20261004-fable`.

- One instrumented `TestOnionLoad` selection made one authenticated attempt inside its
  window and six more added by the instrumented copy after it. All seven ended at the
  data plane's own deadline (30.03–30.12 s, reply `0x06`) while the guest was 79–83%
  idle. Tor joined the rendezvous 245 s after the first authenticated attempt began. The
  next 8 of 8 page loads through the data plane returned 200 in 1.0–4.5 s.
- Thirty connects were made directly against Tor with no data-plane deadline.
  - Sixteen were warm (descriptor cached): fourteen took 1.2–4.2 s and two took 30.0 s
    and 51.1 s.
  - Twelve followed a reset of Tor's onion state. In eleven the descriptor had to be
    fetched: two completed within 3 s, five took 33–87 s and four were failed by Tor at
    119.9–120.5 s. The twelfth found a cached descriptor and took 1.5 s.
  - Two were the first connects on a freshly started Tor at native speed: one was failed
    by Tor after 132 s and one was completed by Tor after 208 s.
- Slow connects occurred at native speed and on both onion services tested.
- First-boot token delivery took 97 s from control-plane start under emulation and was
  acknowledged 51 s into `TestOnionLoad`'s 90 s window. The 2026-10-03 passing run shows
  the same pattern (10 denials before its first authenticated attempt).
- Retained logs show `TestOnionLoad` failed 3 of 6 earlier live selections since
  2026-10-01. The 2026-10-01 failure had no authentication denials and three `0x06`
  replies, so the deadline failed it with the whole window available.
  `TestStreamIsolationPerFirstPartyDomain` failed 2 of 5; its retained logs do not
  distinguish `0x04` from `0x06`, so they do not establish its cause.

Tor's events inside the measured 90 s window were not captured; what Tor was doing in
that window is inferred from the post-window and native measurements. All measurements
are from one evening.

The 30 s value ends connects that Tor completes. `TestOnionLoad` always starts a fresh
Tor, so it always exercises a first connect, inside a window whose comments say it is for
Tor but which also absorbs control-plane start-up.

This ticket corrects the contract value and rationale and makes T033 measure what it
states. It supplies the repair T155 needs to prove HTTPS onion load. It does not close
T155.

## Analysis

- **Must hold:** the data plane's upstream deadline exceeds two of Tor's `SocksTimeout`
  periods. None of the fourteen cold or first connects measured directly against Tor ran
  longer than that. The failure-class mapping, the zeroed failure reply, the
  absence of any post-handshake idle deadline and the absence of per-request records are
  unchanged. T033's timed window opens only when authentication can succeed.
- **Gated:** the replaced production-value test (red on the baseline); a behavioral red
  for T033's gate logic; characterization tests for the unchanged mapping and for an
  abandoned client; a torrc invariant; one to three live selections under a stated stop
  rule; driver verify and the ordinary review gate.
- **Residue:**
  - The gate still depends on public onion availability. Guard: acceptance 8's
    classification, control target and rerun cap.
  - An abandoned client leaves its upstream request pending for up to 250 s instead of
    30 s; the data plane has no connection cap. Guard: the abandoned-client
    characterization test in acceptance 2 and the threat-model note in acceptance 4.
  - Tor can keep a stream pending beyond the deadline: after attachment to a rendezvous
    circuit, after a second descriptor fetch, and for a cached descriptor that advertises
    proof-of-work defences. None of these was observed in the measurements. Guard: the
    existing dial-deadline test pins what the data plane does then; the contract states
    the cases; acceptance 8 stops on a data-plane `0x06`.

## Acceptance

1. Ground the raw measurement files named in Context, the current contract sections and
   the constitution, and record the Constitution Check. Commit a sanitized summary of the
   2026-10-04 measurements as `specs/001-tor-route/evidence/T208-live-results.json`: the
   attempt table, the probe table, the descriptor and phase summaries, and the SHA-256 of
   each raw file. It contains no relay identity, address, cookie or token. State which
   items are measured and which are inferred.
2. Before any production edit:
   a. replace `TestProductionDialDeadlineIsThirtySeconds` with a test of the new contract
      value. This is the red on the baseline.
   b. add, as characterization that passes on the baseline and is labelled as such:
      - a forward test that an upstream reply `0x06` is classified `ROUTE_REFUSED`
        (`0x04`);
      - forward tests, using a stub that withholds its reply until the client has gone,
        that pin what happens then: the upstream connection is closed promptly; bytes the
        client had already sent after its request are forwarded; a client that reset
        makes `Forward` return a write error.
   c. add the torrc invariant case of acceptance 3 as a guard (it passes on the baseline).
   d. add the hermetic gate test of acceptance 7. The pre-fix patch may add only the
      behaviour-preserving seam that test needs, so its red fails on behaviour and not on
      compilation.
   Preserve red and identical-command green with `scripts/test-first-evidence.py`.
3. Apply the maintainer-approved wording verbatim: `contracts/socks5-auth.md` §Deadlines
   (row 1 value, rationale, implementation guidance) and `contracts/torrc.md` invariant
   14, with its case in `tests/contract/torrc/invariants_test.go`. The case checks that
   the golden text has no `SocksTimeout` directive, matching the name the way Tor does
   (case-insensitively and including abbreviations Tor resolves to it: `sockstimeout 300`
   and `SocksTime 300` both fail), and that the shipped `sidecars/tor/torrc` file equals
   the golden byte for byte, so prefixed forms and `%include` cannot slip past and the
   guard holds in a hermetic `verify.sh` run. Change no other contract text.
4. Add the maintainer-approved note to `THREAT-MODEL.md` §5.10 verbatim.
5. Change the production constant to the contract value and correct the comments this
   makes false. Make no other data-plane change: no new flag or environment input, no
   mapping change, no idle deadline, no client-liveness coupling.
6. In `tests/integration/onion_load_test.go`:
   a. after Tor bootstrap, wait within a separate bounded allowance for token delivery to
      read `ACKNOWLEDGED(n)` through `scripts/stargate status`, addressed to the test's
      own project with `STARGATE_PROJECT`, `STARGATE_COMPOSE_FILE` and
      `STARGATE_ENV_FILE` so that nothing is created in the checkout. Exit 0 opens the
      retry window. Exits 20, 30, 50 and 70 mean not yet. Any other exit, or expiry of
      the allowance, fails the test with a message that names token delivery.
   b. set the per-attempt client timeout to the contract deadline plus an allowance for
      TLS and page transfer, so an attempt ends with the data plane's reply class. Set the
      retry window to 390 s, which fits three attempts that Tor fails at 120 s; an
      attempt already running when the window closes finishes, as it does today.
   c. after the reference-onion verdict is known, load the second onion already used by
      T059 once through port 8881 with its own partition username and log the result as
      a control. The pass condition stays the reference onion (spec User Story 1).
   d. correct the header comments that say the window is only for Tor.
7. Add a hermetic test of the gate logic: the window does not open before `ACKNOWLEDGED`;
   the delivery allowance and the failing exits fail loudly; the control result never
   turns a reference-onion failure into a pass.
8. Run the T182 suite live on the final candidate in a disposable guest using the saved
   live-VM procedure, at most three selections. Record each selection in
   `specs/001-tor-route/evidence/T208-live-results.json`: for `TestOnionLoad` the
   delivery wait, every attempt's duration and reply class and the control result; for
   `TestStreamIsolationPerFirstPartyDomain` the per-target outcome it logs; both tests'
   results. That test's own 3-minute client context is shorter than the deadline, so it
   cannot show a data-plane `0x06`; record that limit.
   - A selection may be rerun within the cap only if its failures are of these kinds: a
     `TestOnionLoad` failure in which every failed attempt carried Tor's failure reply
     (`0x04`); a `TestStreamIsolationPerFirstPartyDomain` target that
     `t059ClassifyDialErr` labels as a data-plane failure reply or as the client window
     being exceeded. Two asymmetries are accepted and recorded with the result: the
     data-plane-reply label does not distinguish `0x04` from `0x03`, `0x01` or `0x06`,
     and the client-window label can hide a reply the data plane would have sent later.
   - Every other failure stops the ticket for a report to the maintainer, with no rerun:
     any `TestOnionLoad` attempt ending in the data plane's `0x06` or in `0x03`; an
     authentication denial after acknowledgement; a TLS, HTTP or transfer error; expiry
     of the delivery or bootstrap allowance; a harness or provisioning error; in the
     stream-isolation test, the authentication label, the listener-unreachable label,
     an unclassified result or any later assertion failure.
   - Closing needs each of the two tests to have passed in at least one selection. If
     three selections do not provide that, stop and report. Every selection is disclosed
     with counts; SKIP is never PASS.
9. Sweep for every statement this ticket makes false, with the grep recorded. Known:
   comments naming the 30 s upstream deadline in `forward/tor.go`, `listener/socks5.go`,
   `tests/integration/fake_socks5_tor.go` and `fake_socks5_tor_test.go`; the comments in
   `tests/contract/control-grpc/cold_start_snapshot_test.go` and `watch_events_test.go`
   that cite the contract for a 30 s worst-case dial; comments naming T033's 90 s window in
   `tests/contract/tor/username_less_isolation_test.go`,
   `tests/integration/same_origin_shared_circuit_test.go` and
   `tests/integration/stream_isolation_test.go` (one comment line; no behaviour change);
   the "13 invariants" header text and the description of what the case reads in
   `tests/contract/torrc/invariants_test.go`; the
   pending T067 and T072 ticket statements and the T072 line in `tasks.md`. Record what
   is left and why (quoted historical text).
10. Run `scripts/verify.sh` on the exact candidate, pass the ordinary review gate, and
    record the Constitution VIII impact assessment below.

## Grounded files budget: 23 paths

Every path implements an acceptance item or repairs an orphan this change creates.

1. `specs/001-tor-route/tickets/T208-raise-tor-upstream-deadline.md`.
2. `specs/001-tor-route/STATUS.md`.
3. `specs/001-tor-route/evidence/T208-tests-first.json` (new).
4. `specs/001-tor-route/evidence/T208-live-results.json` (new, sanitized).
5. `specs/001-tor-route/contracts/socks5-auth.md`.
6. `specs/001-tor-route/contracts/torrc.md`.
7. `THREAT-MODEL.md`.
8. `data-plane/internal/forward/tor.go`.
9. `data-plane/internal/forward/tor_test.go`.
10. `data-plane/internal/listener/socks5.go` (comment).
11. `tests/contract/torrc/invariants_test.go`.
12. `tests/integration/onion_load_test.go`.
13. `tests/integration/onion_load_gate_test.go` (new; name may differ).
14. `tests/integration/fake_socks5_tor.go` (comment).
15. `tests/integration/fake_socks5_tor_test.go` (comment).
16. `tests/integration/same_origin_shared_circuit_test.go` (comment).
17. `tests/integration/stream_isolation_test.go` (one comment line).
18. `tests/contract/tor/username_less_isolation_test.go` (comments).
19. `tests/contract/control-grpc/cold_start_snapshot_test.go` (comment).
20. `tests/contract/control-grpc/watch_events_test.go` (comment).
21. `specs/001-tor-route/tickets/T067-contract-test-testscontracterror-templat.md`.
22. `specs/001-tor-route/tickets/T072-extend-data-planeinternalforwardtorgo-fr.md`.
23. `specs/001-tor-route/tasks.md`.

## Out-of-scope

Changing the failure-class mapping or reply bytes; tying the upstream dial to client
disconnect; any other torrc change; every change to
`tests/integration/stream_isolation_test.go` beyond the one comment line, and every other
file in T155's candidate; T155's evidence and closure; the host-direct live tier (T202);
designing the pending T067/T067a/T067b contract tests.

## Filing and sequencing

T155 and T078 depend on T208. T155 is parked before filing, because filing moves HEAD;
it is reopened on the new HEAD after T208 commits and reconciles its preserved candidate
against it, including the one comment line T208 changes in
`tests/integration/stream_isolation_test.go`. T208 changes none of T155's evidence. The
approved T202, T200, T201 sequence after T155 is unchanged.

## Constitution VIII impact assessment

T208 lengthens one existing data-plane deadline and changes one live test's time budget.
It adds no route, listener, identity or stored record, and it leaves the failure mapping
and reply bytes unchanged. It lengthens the time an abandoned request can stay pending at
the Tor sidecar, which the threat-model note records. The ordinary ticket review and one
guest's live evidence do not approve a release; Constitution VIII's cumulative milestone
review and external human release review remain open, and T155 still owns the integrated
foundation evidence.
