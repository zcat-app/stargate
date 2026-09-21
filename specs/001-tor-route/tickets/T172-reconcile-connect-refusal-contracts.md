---
id: "T172"
title: "Reconcile Tor HTTP CONNECT refusal contracts"
status: done
created: "2026-09-21"
last_updated: 2026-09-21
source: "T147 investigation and recommendation"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T147"]
parallel: false
files_budget: 40
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
reviews: { round: 2, date: 2026-09-21, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T172: Reconcile Tor HTTP CONNECT refusal contracts

## Context

T147 recommends refusing HTTP CONNECT because it has no first-party partition. Before the
runtime change, reconcile the legacy success/error promises and every affected test consumer.
This is a normative document change, not implementation or a claim of repaired isolation.

## Analysis

- Must hold: unsupported HTTP cannot reach Tor; supported SOCKS retains device/profile/site
  identity, authentication, no destination DNS and CP-independent byte forwarding.
- Gated: ticket lint, dependency graph and exact-candidate verification check consistency.
- Residue: independent review must detect lost privacy coverage or a remaining authoritative
  HTTP-success promise. T173 supplies runtime falsifiers; T126/T155 supply circuit evidence.

## Acceptance

1. Adopt T147's exact target for Tor port 8881: demux `C` closes with zero response bytes,
   no auth evaluation, no counter increments and no upstream socket. No HTTP success,
   error-template ingress, negotiation extension, fallback or configuration bypass remains
   supported. Preserve authenticated SOCKS behavior; distinguish HTTP CONNECT from the SOCKS
   CONNECT command throughout. No decision about other routes is implied.
2. Reconcile `specs/001-tor-route/spec.md`, `plan.md` Constitution Check,
   `contracts/foundation-boundaries.md`, `contracts/socks5-auth.md`,
   `contracts/error-template.md`, `contracts/control-grpc.md`, `data-model.md`,
   `specs/000-architecture/spec.md`, `ARCHITECTURE.md`, `THREAT-MODEL.md` and applicable
   quickstart/README guidance. Search current normative consumers before editing; each
   remaining HTTP mention must be historical, a future format, a refusal or another route.
   State clearly that current code still conflicts until T173; do not label the target PASS.
3. Record a per-file/per-invariant inventory for T173 covering at least
   `data-plane/internal/listener/{connect,socks5}_test.go`,
   `data-plane/internal/forward/tor_test.go`, `tests/contract/socks5/`,
   `tests/contract/error-template/`, `tests/contract/control-grpc/` and affected integration
   helpers. Map each HTTP-dependent test to refusal, equivalent SOCKS transport coverage,
   or renderer-only coverage. Preserve every invariant named in T147's coverage migration;
   no silent deletion, skip or relaxation to make removal green.
4. Reconcile pending consumer acceptance T064–T073 (including T067a/b and T070a/b), and
   relevant T123/T132/T126 instructions, to the selected ingress. Preserve their underlying
   privacy tests and measurable outcomes; existing completed tickets are historical and are
   not rewritten. Keep T173 a blocker of T155/T123/T132 (T126 via T132 and US3 via T155).
   Check the dependency graph for cycles; T173 cannot depend on its own consumers.
5. Publish the pre-release breaking migration described by T147: stop old admission/restart
   DP, no mixed-version safety claim, extension stays on SOCKS, no generic constant-username
   SOCKS or Direct workaround, context-incapable clients unsupported. Explicitly assess
   existing tunnels, credentials/snapshots, fixed route configuration and remaining live gaps.
6. Run ticket lint and `bash scripts/verify.sh`; independently review normative consistency
   under Principles I/III/V/VIII. Pure document work uses consistency evidence, not a fabricated
   runtime red/green sequence. If the inventory exceeds 40 files, stop for refinement before
   expanding it. Do not resolve any new policy conflict by weakening the constitution.

## Out-of-scope

Production source/test implementation, SOCKS identity redesign, Tor configuration changes,
other routes, constitution amendments, risk acceptance, or marking M2 repaired. Test edits
and the new failing regression belong to T173 after these contracts have been reviewed.

## Notes

The budget includes the ticket and derived STATUS board, normative docs and pending tickets.
T173 is a combined regression/fix owner so no permanently red test dependency is created.

## Selected target and current-state boundary — 2026-09-21

T147's reviewed selection is now the normative target for Tor port 8881:
first byte `C` closes with zero response bytes, no auth evaluation, no
request/byte counter increment and no upstream socket. It does not parse
further HTTP bytes or provide a success, error-template, negotiation,
configuration, retry or Direct-fallback path. Authenticated SOCKS5 keeps the
complete device/profile/initiating-site `sg1:` username, bearer validation,
hostname-form target and opaque byte pipe. A SOCKS5 **CONNECT command** remains
supported; an HTTP **CONNECT method** does not. No other route is decided here.

This is a pre-release breaking transition. Stop old admission and restart the
DP with the T173 binary; existing old-process tunnels close on restart. No
mixed-version service window is certified. The extension already uses SOCKS5h.
Third-party clients need the complete bearer and trustworthy T136 partition;
a generic `socks5h` URL with a constant username or a Direct workaround is
invalid. Context-incapable clients must stop protected requests. Existing
credentials and valid auth snapshots need no schema rewrite, and fixed route
binding and Tor configuration need no change; their continued validity only
applies to authenticated SOCKS and normal generation/revocation rules. T173
must measure the stop/restart and new listener. Local deployed refusal,
LAN/VPS outcomes, browser behavior and real circuit separation remain open.
Current `listener/connect.go`, `Tor.Dial` and HTTP-positive tests contradict
the target until T173; this T172 document is not a runtime PASS or an M2 fix.

## T173 per-file coverage migration inventory

The disposition column is an executable acceptance for T173, not permission
to delete a test without retaining its invariant. `Refusal` means real client
socket plus observable fake upstream; `SOCKS` means authenticated SOCKS5
CONNECT with the complete partition identity; `renderer` means direct
format/render calls without port-8881 ingress. A test already on SOCKS stays
as a positive control. T173 records each changed/deleted test against this
inventory and supplies a green replacement; all current HTTP-positive tests
are expected to fail against the new target until migrated.

| Existing file | Current HTTP dependence / preserved invariant | T173 disposition |
|---|---|---|
| `data-plane/internal/listener/connect_test.go` | HTTP 200 and early bytes; malformed/missing auth and counter silence; oversized/slow framing; route-error template; pipe close without injected bytes | Refusal cases for valid/missing/malformed/claimed identity/pipelined/slow/oversized input, zero bytes/auth/counters/dials; move early-byte, route-failure and pipe-close invariants to SOCKS tests; renderer-only format checks direct |
| `data-plane/internal/listener/socks5_test.go` | `TestDemux_ConnectRouted` requires HTTP dispatch; other tests pin SOCKS method/auth/request failures | Replace demux HTTP success with silent `C` refusal and zero effects; retain all SOCKS tests, especially mixed-method refusal and zeroed failure BND |
| `data-plane/internal/forward/tor_test.go` | `TestDialNoUsernameOffersNoAuthAndBridges` proves defective HTTP seam; other tests pin username, target, deadline, counters and bytes | Remove positive NO_AUTH path with its production seam; replace with listener refusal plus SOCKS distinct-username/empty-password positive control; retain hostname-form, deadline, byte flush, early/long-lived pipe and route errors |
| `tests/contract/socks5/demux_test.go` | `C` routed to HTTP, often expecting 407 | Refusal: `C` yields zero bytes/EOF with no auth/counter/upstream; retain 0x05 method selection and unknown-byte refusal |
| `tests/contract/socks5/connect_auth_success_test.go` | HTTP 200/relay | Refusal for valid-looking bearer; SOCKS success to same fake upstream proves admission, exact identity, target and bytes |
| `tests/contract/socks5/long_lived_connect_test.go` | Mixed HTTP/SOCKS long-lived byte pipe | SOCKS-only 30 s+ bidirectional interleaved small/large/asymmetric/idle traffic, exact bytes and close initiated by either end; retain no per-request log assertion |
| `tests/contract/socks5/auth_failure_counter_test.go` | Mixed HTTP/SOCKS invalid bearer counts | SOCKS malformed/missing/invalid/empty-generation failures keep zero request/byte delta; HTTP `C` with all bearer variants also zero under refusal; `GetStatus` no-traffic sandwich remains |
| `tests/contract/socks5/auth_passed_counter_test.go` | Mixed HTTP/SOCKS success count/bytes | SOCKS-only N authenticated forwards retain exact N request and `2B×N` byte delta, adjacent-hour handling and no per-request log; refusal never enters pass count |
| `tests/contract/socks5/auth_required_test.go` | SOCKS-only auth failure | Retain exact `01 FF`, EOF, no token leak and no counter increment |
| `tests/contract/socks5/leak_test.go` | SOCKS-only response/log leak scan | Retain destination/token/username absence and fixed diagnostic vocabulary |
| `tests/contract/socks5/no_per_request_logs_test.go` | SOCKS-only success log allowlist | Retain canonical allowlist; apply to refusal and migrated long-lived/counter tests |
| `tests/contract/socks5/userpass_success_test.go` | SOCKS-only positive auth | Retain exact method/sub-negotiation and complete identity control |
| `tests/contract/error-template/auth_required_test.go` | HTTP 407 ingress; indistinguishable missing/malformed body | Renderer-only 407/body/header/leak and permitted reference-ID comparison; move missing/malformed ingress outcome to refusal and SOCKS auth tests |
| `tests/contract/error-template/header_set_test.go` | HTTP ingress for all four codes | Renderer-only four-header exact order/absence, length, status, full leak scan for all codes; route outcomes move to SOCKS failures, no Tor HTTP-response claim |
| `tests/contract/control-grpc/dpharness_test.go` | Harness address comment says SOCKS5/CONNECT; auth helper already SOCKS | Rename scope to SOCKS-only; retain socket and auth helper behavior |
| `tests/contract/control-grpc/reload_tokens_test.go` | SOCKS auth state | Retain generation application/revocation assertions independent of HTTP |
| `tests/contract/control-grpc/cold_start_snapshot_test.go` | SOCKS admission, snapshot and fixed route reply | Retain CP-down restore, exact SOCKS reply and EOF; refusal must not read snapshot/auth |
| `tests/contract/control-grpc/watch_events_test.go` | SOCKS probe for advisory-event behavior | Retain reachable-upstream positive control and stale/unhealthy/CP-disconnect independence; no HTTP conversion |
| `tests/contract/control-grpc/transport_test.go` | IPC transport only | Retain identity/transport checks; no ingress change |
| `tests/integration/fake_socks5_tor.go`, `fake_socks5_tor_test.go` | Observable upstream accept, usernames and relay; no HTTP ingress dependency | Retain as refusal zero-dial observer and SOCKS positive control, including target/credential capture and byte relay |
| `tests/integration/dns_leak_test.go`, `onion_load_test.go`, `stream_isolation_test.go`, `same_origin_shared_circuit_test.go`, `circuit_isolation_corpus_test.go`, `stack_smoke_test.go` | Already SOCKS CONNECT; DNS, live onion, partition circuits and app bytes | Retain as positive controls; do not recast SOCKS command references as HTTP. T126/T155 still own same-target and browser evidence |
| Planned `tests/contract/socks5/route_failure_counter_test.go`, `request_phase_failures_test.go` (T067b/T067a) | Historical plan mixes HTTP for counters; fixed SOCKS replies already selected | SOCKS-only auth-passed failure count and exact `03/04/06` replies, zero BND/bytes, EOF and leak scan; HTTP refusal count is separate |
| Planned `tests/integration/error_template_test.go`, `circuit_drop_midstream_test.go` (T070/T070a) | Historical HTTP response and ambiguous CONNECT wording | SOCKS route-down reply and mid-pipe zero-injection/no-retry/close; renderer format is separate |

T025a/b/c/d and T026/T027/T043/T048/T068a are completed historical
tickets; their code coverage is migrated above, but their approval records
are not rewritten. T064–T073 and T079a now carry selected acceptance sections
that supersede their quoted `tasks.md` history. T123/T132 use SOCKS for their
start/reconnect/CP-down probes; T126 remains actual same-target circuit and
credential-fusion evidence. T173 blocks T155/T123/T132 directly, and T126
through T132. These dependencies were checked for cycles; T173 depends only
on T147/T172 and none of its consumers.

## Consistency evidence and residue

`lint-ticket.py`, the dependency graph and `scripts/verify.sh` are the
mechanical gates for this document change. The falsifiers for this candidate
are any remaining current Tor HTTP success/error promise in authoritative
sources, any consumer that silently loses a privacy assertion, or a dependency
cycle. Independent review must search for those falsifiers under Principles
I/III/V/VIII. T173 owns runtime red-before-green and deployed refusal; T126/T155
own circuit and browser outcomes. No synthetic document test is a runtime red.
