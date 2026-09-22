---
id: "T173"
title: "Refuse unpartitioned HTTP CONNECT on the Tor listener"
status: in-progress
created: "2026-09-21"
last_updated: 2026-09-22
source: "T147 investigation and recommendation"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T147", "T172"]
parallel: false
files_budget: 44
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs:
  - ".specify/memory/constitution.md Principles I/II/III/V/VII/VIII"
  - "specs/001-tor-route/spec.md FR-005–FR-009"
  - "specs/001-tor-route/contracts/foundation-boundaries.md §Negotiation and isolation"
  - "specs/001-tor-route/contracts/socks5-auth.md §HTTP CONNECT refusal"
decision_refs:
  - "specs/001-tor-route/tickets/T147-resolve-connect-isolation-contract.md §Investigation and recommendation"
remediates: "T043"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T173: Refuse unpartitioned HTTP CONNECT on the Tor listener

## Context

Implement T147's recommended refusal after T172 reconciles the authoritative wire and consumer
contracts. Current authenticated HTTP CONNECT reaches Tor with NO_AUTH and cannot represent
its initiating-site/profile partition. This child closes the implementation finding, not T147.

## Analysis

- Must hold: HTTP bytes cannot produce authentication, counters, upstream traffic or a tunnel;
  no fallback. SOCKS admission, isolation username, empty upstream password, hostname forwarding
  and opaque byte-pipe semantics remain unchanged, including CP outage/advisory-event failure.
- Gated: new real-socket refusal regression plus preserved/migrated auth, counters, logs,
  errors and long-lived tests; `scripts/verify.sh` on the exact candidate.
- Residue: fake sockets cannot prove deployed wiring or Tor circuit separation. Require the
  deployed Local refusal/SOCKS positive control here; T126/T155 remain circuit/browser owners.

## Acceptance

1. Before changing production code, add
   `TestHTTPConnectSameDestinationDistinctFirstPartyRefused` as specified in T147: same
   destination, distinct synthetic initiating-site/profile/device identities, valid bearer
   and missing/malformed variants, non-authoritative identity hints, payload/slow/oversized
   cases. Observe real client and upstream sockets: zero reply bytes, client close, zero
   upstream accepts and unchanged request/byte counters. Preserve the pre-fix failure caused
   by actual upstream admission/HTTP success, not unavailable tooling or an invalid fixture.
   Add a paired SOCKS positive control with intact distinct T136 usernames and empty upstream
   passwords to the same fake Tor endpoint; a disconnected fixture must fail the control.
2. Implement the reviewed T172 refusal contract at the production demux and remove the
   obsolete HTTP forwarding path (`Tunneler`, `Tor.Dial`/`Pipe` and their wiring as appropriate).
   No HTTP parser or request-specific decision is needed to refuse `C`. Do not change working
   SOCKS auth/partition semantics or relax its deadlines. Show the named regression green
   after the fix with the same test and record both source snapshots/commands/results.
3. Execute T172's coverage-migration inventory with the renderer ownership refinement below. Replace HTTP success/route fixtures
   with authenticated SOCKS for still-supported properties: byte integrity including early
   bytes, long-lived pipes, CP-outage survival, advisory-event independence, auth/counter
   distinctions, leak invariants and mid-tunnel failure. Retain renderer-only tests only with
   accurate scope. Update the NO_AUTH-positive `TestDialNoUsernameOffersNoAuthAndBridges`
   assertion because its production seam is removed. Every changed/deleted test needs an
   invariant mapping; no skip gates, weakened assertions or missing-suite workaround.
4. Prove the production binary in the actual Local Compose deployment refuses HTTP CONNECT
   with valid/missing/malformed credentials and claimed identity: no returned bytes and no
   DP-to-Tor socket connection during these probes. A following authenticated SOCKS request
   through the same bound listener must reach real Tor and return destination bytes. Observe
   the upstream boundary with a positive capture/trace control and identify the candidate,
   image, namespace and environment. Do not infer zero upstream traffic only from a failed
   client connection. Required unavailable evidence leaves this ticket unfinished.
5. Update THREAT-MODEL and the T172 transition record from target to implemented/verified
   only for measured claims in this ticket and current contracts; retain T172's historical
   approval record and identify the superseding transition here. Test/record the stop-and-restart migration; no HTTP compatibility
   switch or Direct fallback. Existing live evidence is not automatically transferred to the
   new candidate. Same-target actual circuit separation and browser fallbacks remain T126/T155.
6. Run `bash scripts/verify.sh`, the affected real-socket contract suites and required Local
   deployment probes, then the normal independent review gate. T155/T123/T132 remain blocked
   until completion. If the refined inventory exceeds 44 changed files, refine/decompose before
   editing beyond budget, retaining an atomic red-before-green regression/fix and all blockers.

## Out-of-scope

Constitution changes, HTTP identity-header support, changing SOCKS first-party derivation,
other routes, implementing the three future HTTP route renderers, or accepting missing live evidence. Test changes in acceptance item 3 are
explicitly authorized only to migrate unsupported HTTP behavior while preserving its
underlying privacy coverage; completed historical ticket records are not edited.

## Notes

`tests_first: []` means the new failing regression and fix are in this same atomic ticket,
not that Principle VII is waived. T172 must finish the normative mapping before this starts.

## Authorized refinement — renderer ownership

The maintainer authorized this refinement after evaluation in the working session. It
supersedes only T172's all-four-code renderer migration row and the corresponding current
error-template contract requirement; all refusal, SOCKS, live evidence and review obligations
above remain binding. T172's completed record remains historical.

- T173 migrates the implemented AUTH_REQUIRED renderer assertions to direct production-renderer
  calls: exact status, four-header order/absence/length, body and permitted substitutions,
  reference-ID shape/freshness/only-variable-bytes, and full response leak scans. Missing and
  malformed client credentials remain covered at the actual SOCKS/refusal ingress.
- Preserve named checks that each unsupported ROUTE_DOWN/REFUSED/TIMEOUT renderer call returns
  an error and emits zero bytes. These checks describe current behavior; they do not substitute
  for positive format coverage. Remove obsolete ingress/implementation-marker skip gates from
  the migrated suite, mapping their unimplemented positive assertions explicitly to T071.
- T071 owns one atomic tests-first implementation of all three future renderer codes and all
  four codes' positive status/header/body/reference-ID/leak assertions. T068/T069 are deferred
  and replaced by that owner; their downstream blockers transfer to T071. New renderer tests
  must fail for the missing behavior before implementation, then pass in the same ticket.
- Reconcile the current error-template contract and dependency graph without a cycle or a
  runnable consumer of a deferred test. No existing green privacy assertion is discarded.

The 44-file cap covers the previous 32-path forecast plus six renderer ownership/consumer
records (T068/T069/T071/T072/T078/T079), test-access/deployment harness paths and evidence.
It authorizes only acceptance-linked migration and ownership edits, with an exact touched-path
inventory before review; it does not expand runtime behavior beyond HTTP refusal.

## Execution record (2026-09-22)

The authorized refinement, runtime refusal and coverage migration are implemented.
The unchanged named regression has behavioral red/green results; affected suites
and trace-verdict selftests pass. The exact invariant mapping, candidate identities,
failed setup and successful Local rerun are recorded in
[the evidence report](../analysis/T173-connect-refusal-evidence.md).

The actual Local deployment passed stop/restart, retained-snapshot admission with
CP stopped, silent HTTP refusal with zero traced DP-to-Tor connects, and a following
SOCKS real-Tor destination-byte control. The initial emulation/setup failure was
resolved without changing production settings or waiving any assertion. T172's
historical approval remains unchanged; this is its measured transition record.
Final verification, independent review and the completion status are driver-owned.
