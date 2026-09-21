---
id: "T147"
title: "Resolve HTTP CONNECT first-party isolation"
status: done
created: "2026-09-12"
last_updated: 2026-09-21
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T043", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: ["specs/001-tor-route/contracts/foundation-boundaries.md §Negotiation and isolation"]
remediates: "T043"
tests_first: []
reviews: { round: 1, date: 2026-09-21, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T147: Resolve HTTP CONNECT first-party isolation

## Context

Audit transport M2: supported HTTP CONNECT passes no upstream isolation credential, unlike the extension SOCKS path; Constitution III has no corresponding exception.

## Analysis

- Must hold: Constitution I/III permits bounded negotiation but no inferred first party from
  application headers; every supported Tor ingress needs device/profile/initiating-site isolation.
  Destination-only, bearer-only and per-connection identities do not implement that partition.
- Gated: existing forward tests observe real socket handshakes and preserve SOCKS usernames,
  but `TestDialNoUsernameOffersNoAuthAndBridges` positively requires the CONNECT defect.
  Ticket lint and dependency consistency check planning structure, not runtime isolation.
- Residue: only independent review can check this recommendation's completeness. T172 owns
  normative/consumer reconciliation; T173 owns red-before-green refusal, retained SOCKS coverage
  and deployed refusal evidence. T126/T155 retain real circuit and browser integration evidence.
  This document does not certify the existing code or waive any constitutional property.

## Acceptance

1. Trace authenticated CONNECT through Tor.Dial and document the existing NO_AUTH behavior and available first-party context.
2. Compare an explicitly supported first-party transport contract with refusal of an ingress that cannot meet the invariant; destination-only isolation is not equivalent.
3. Specify a same-destination/distinct-first-party regression and migration behavior before implementing any contract decision.
4. Return a reviewable recommendation under the T156 constitution; no silent privacy exception or implementation is authorized by this investigation ticket.

### Required planning refinement


Completion requires a reviewed recommendation and concrete implementation follow-up tickets with
`remediates`, spec/contract references, a tests-first regression, and measurable closure criteria.
Before marking this investigation done, add every required follow-up to T155 `blocked_by`
and to affected consumers (including deployment, CONNECT tests, or event consumers as applicable).
A recommendation alone does not close the finding. Unresolved authoritative conflicts remain
blocking; this ticket cannot authorize a constitution amendment or accept the risk.

## Out-of-scope

Constitution amendment, target-based isolation presented as first-party isolation, or modifying the working SOCKS path.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.


## Investigation and recommendation — 2026-09-21

### Observed path and falsification

Grounded at `c215ecddafbb4c4bcd44e723ae6111d6dc62d25e`, before this document change:

1. `data-plane/internal/listener/socks5.go` dispatches the first byte `C` to
   `Deps.Connect`; `data-plane/cmd/stargate-proxy/main.go` wires it to `HandleConnect`.
2. `listener/connect.go` reads at most an 8 KiB negotiation block, interpreting the
   authority and `Proxy-Authorization: Bearer` only. It validates the 32-lowercase-hex
   token, receives a boolean verifier result, and increments the admitted-request counter.
   It has no browser-profile or initiating-site field. Other headers are discarded.
3. `Tunneler.Dial(authority)` reaches `forward.Tor.Dial`, which calls
   `dialUpstream(nil, target)`. A nil `proxy.Auth` offers only SOCKS `NO_AUTH` upstream.
   The destination goes in hostname form, but there is no isolation username or password.
   A successful upstream handshake yields HTTP 200 and a byte pipe.
4. By contrast, `Tor.Forward(client, uname, target)` passes the SOCKS username intact and
   uses an empty upstream password. The extension's T136 `sg1:` identity represents
   device/profile/context/initiating site; the bearer is not forwarded to Tor.

Falsifier: an existing profile/site input or upstream auth sub-negotiation on `Tor.Dial`
would disprove the trace. Inspection found neither. The following existing real-socket
probes passed on 2026-09-21 (three selected tests, no live Tor):

```bash
cd data-plane
go test ./internal/forward -run 'TestDialNoUsernameOffersNoAuthAndBridges|TestForwardPassesUNAMEVerbatimAsUpstreamUsername|TestForwardUnixSocketPreservesSOCKS5hAuth' -count=1
```

The first explicitly verifies NO_AUTH and absence of sub-negotiation; the other two are
SOCKS positive controls. This is retrospective evidence of the gap, not a new failing
regression or proof that two real Tor streams shared a circuit. The old T043 exception
and old HTTP-success contract are superseded by T156's foundation boundary; no affected
production implementation is authorized by this investigation.

### Alternatives

| Candidate | Required mechanism and tradeoff | Recommendation |
|---|---|---|
| Supported first-party HTTP transport | A newly specified proxy-negotiation field, e.g. `Proxy-Stargate-Isolation: sg1:<64 lowercase hex>`, could carry the T136 representation, independently of the bearer. A supported client must derive it from trustworthy browser context, not the target. Require exactly one field, no folding/duplicates, bounded 8 KiB total negotiation, fixed malformed/missing refusal, an identity-bearing dial seam, intact upstream username and empty password, plus client and real circuit evidence. The current extension emits SOCKS descriptors; no such HTTP client is implemented/tested here. | Technically conforming candidate only; not selected or authorized. A header alone proves neither context fidelity nor cross-device partitioning. |
| Refuse HTTP CONNECT on the Tor listener | Refuse the unsupported ingress before authentication, counters or upstream dial; existing browser SOCKS selection supplies its defined context. Breaks legacy HTTP proxy clients and requires explicit migration and coverage preservation. | Selected recommendation under T156's explicit refusal option. |
| Derive identity from destination, bearer, source address or a random connection id | Destination cannot distinguish two top-level sites loading the same resource; bearer/source omits site and profile; randomness does not carry the required context. Reading Host/Origin/Referer or tunneled TLS cannot supply trustworthy initiating context and exceeds the permitted contract. | Rejected. No privacy exception. |

### Proposed refusal and migration (target, not current behavior)

T172 first reconciles the normative contract; T173 then implements it with tests first.
Port 8881 retains authenticated SOCKS5. HTTP CONNECT is unsupported: on demux byte `C`,
close without writing response bytes, consulting authentication, incrementing request/byte
counters, or opening any upstream socket. Other unsupported first bytes retain their
existing refusal. No HTTP 200, 407, route-error HTML, protocol auto-conversion, retry,
configuration opt-out or fallback to Direct is permitted on this path. This is protocol
refusal, not evidence of token failure or Tor unavailability. A bounded first-byte read
continues to use the listener's handshake deadline. Do not parse the remaining headers.

This recommendation removes the unauthenticated-isolation `Dial`/`Tunneler` production
path, while leaving the working SOCKS path's auth, opaque identity and byte pipe intact.
Renderer-only tests can remain as future-format tests if explicitly labelled; they must
not claim that an HTTP response is reachable from port 8881. Transport guarantees now
exercised using HTTP fixtures must be retained through authenticated SOCKS fixtures.

Pre-release migration is deliberately breaking. Document it before T173 lands; stop
admission and restart the DP with the repaired binary (existing old-process pipes close
on restart). No mixed old/new service window is certified. The Stargate extension already
uses SOCKS5 and needs no CONNECT fallback. Third-party clients must implement the complete
SOCKS5h bearer plus trustworthy T136 partition contract; selecting a generic `socks5h`
URL with a constant username is insufficient. Clients without that context are unsupported
and must stop protected requests. Never recommend changing to a direct proxy on refusal.
No deployed credentials, auth snapshot schema, route binding or Tor configuration changes
are required. LAN/VPS exposure is not authorized by this Local-feature recommendation.

### Required regression and coverage migration

T173 adds `TestHTTPConnectSameDestinationDistinctFirstPartyRefused` **before code**.
Use a real TCP listener and observable fake Tor socket. Send two authenticated-looking
HTTP CONNECTs for the identical destination with distinct synthetic T136 site identities
in non-authoritative header hints (also vary profile/device in subcases). Neither reaches
Tor: zero accepted upstream sockets, zero reply bytes, closed clients, unchanged counters.
Include missing, malformed and valid bearer cases, headers claiming isolation, pipelined
payload and slow/oversized input; refusal cannot depend on any of them. The pre-fix valid
case must fail by reaching the upstream/HTTP success path, not by a fixture/tool failure.

A paired authenticated SOCKS positive control reaches that same fake upstream with two
distinct `sg1:` usernames preserved byte-for-byte and empty upstream passwords. It proves
that a broken or disconnected listener cannot make zero-dial assertions pass vacuously.
T126/T155 still require actual same-destination/distinct-partition circuits and a
credential-fusion control; fake handshakes do not establish Tor circuit separation.

T172 inventories each existing and planned HTTP test and maps it to one of:
HTTP refusal; SOCKS auth/route/byte-pipe test retaining the old invariant; renderer-only
format test with no ingress claim. In particular retain long-lived/early-byte integrity,
CP-down and advisory-event independence, auth-failure and auth-pass counter semantics,
no per-request logs, route failures, leak corpus and mid-tunnel close semantics.
Do not turn removed HTTP support into skipped or deleted privacy coverage.

### Delivery and consumer blockers

- **T172**: reconcile feature/architecture/plan and wire contracts, migration guidance,
  and pending CONNECT consumer acceptance. No runtime implementation. Explicitly list
  current-code conflicts and the exact T173 test migration inventory.
- **T173** (depends on T172): implement refusal and remove its obsolete forwarding seam,
  author the named regression first, migrate affected tests, and prove refusal plus
  authenticated SOCKS forwarding on the deployed Local DP. Only then is M2 repaired.
- Both children directly block **T155**, **T123** (fresh deployment) and **T132**
  (reconnect/CP-down consumers). **T126** already depends on T132, so it is transitively
  gated on both. **T064–T073**, including T067a/b and T070a/b, already depend on T155;
  they cannot run against stale HTTP acceptance. T172 must reconcile that acceptance
  before its own completion. The shared Compose-runner-only T121 is unaffected.
- Completed T026/T043 and other historical tickets stay unchanged. The live T163/T165
  evidence remains evidence for its recorded candidate, not post-repair ingress evidence.

Constitution check: I retains payload opacity and fixed routing; II retains SOCKS service
under CP outage; III removes an ingress without the required context, with no downgrade;
V records current exposure and evidence limits; VII requires real-socket red-before-green
in T173, while this document uses consistency checks; VIII requires the normal independent
review set for this recommendation and each child. IV/VI have no dependency/build change.
The decision narrows supported ingress within T156's explicit permission, without an
amendment or accepted finding. T147 completion closes planning only; T155 remains blocked.
