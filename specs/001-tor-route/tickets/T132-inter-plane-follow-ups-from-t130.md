---
id: T132
title: 'Inter-plane follow-ups from T130 (re-push, ALPN pins, fakecp ALPN)'
status: pending
created: 2026-09-07
last_updated: "2026-09-21"
source: hand-filed (T120 convention; T130 rounds 1–2 review follow-ups + audit plan)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T130", "T139", "T135", "T137", "T148", "T156", "T159", "T172", "T173"]
parallel: false
files_budget: 6
privacy_critical: true   # re-push semantics touch the auth-generation delivery path
complexity: medium
risk: medium
round_cap: 2
spec_refs:
   - specs/001-tor-route/contracts/control-grpc.md §"Plane-down survival"   # the row the re-push gap arguably falls short of
   - specs/001-tor-route/contracts/wire-auth.md §4   # the ALPN invariant (as amended by T130)
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T132: Inter-plane follow-ups from T130 (re-push, ALPN pins, fakecp ALPN)

## Context

Three follow-ups the T130 review identified as out-of-diff (deliberately
not expanded into T130's rounds), plus one semantics gap observed live.
Filed as ONE ticket to avoid follow-up sprawl; each bullet is small and
all sit on the same surface.

1. **DP-restart re-push gap (the real one).** The CP pushes
   ReloadTokens at ITS boot (§1.8 containment — "next boot re-syncs").
   If the DP restarts while the CP is up: the DP's WatchEvents client
   reconnects (live-observed; grpc retries forever), but nothing
   triggers a NEW push — the DP comes back with an empty generation and
   stays auth-dead until the CP restarts. control-grpc.md's "Plane-down
   survival" row covers the CP-down direction; the DP-down direction is
   unspecified. Candidate shape: the CP re-pushes the current generation
   when the WatchEvents stream (re)establishes — a WatchEvents semantic,
   i.e. SPEC work first (escalate per the menu if the contract owners
   disagree with the reading).
2. **Java-side ALPN is satisfied only by library default.** wire-auth §4
   (as amended) demands exactly `["h2"]` on every TLS endpoint; CpTls
   relies on GrpcSslContexts' default application-protocol config rather
   than an explicit list. Pin it explicitly (comment + code) so a
   grpc-java upgrade changing defaults cannot silently drop h2.
3. **fakecp.StartTLS offers no ALPN h2.** The Go fake CP's TLS server
   does not set NextProtos — Go↔Go tolerates it (both sides skip ALPN),
   which is exactly the mutually-underspecified shape that hid T130's
   ALPN half. Give the fake the `["h2"]` shape so the test tier mirrors
   the Java peer's strictness.

## Analysis

*(Quick pass; bullet 1 is the only design item — the rest are pins.)*

## Acceptance

1. Bullet 1: decision recorded (contract amendment or explicit
   accepted-residue in SECURITY-DECISIONS.md if the survival row is read
   as CP-only); if amended, the CP re-pushes on WatchEvents
   (re)establish and a DP-restart-while-CP-up integration probe (the
   T131 smoke's sibling) goes green.
2. Bullet 2: CpTls sets the h2 application protocol explicitly; a
   comment cites wire-auth §4.
3. Bullet 3: fakecp's TLS server offers exactly ["h2"]; the control-grpc
   suite stays green.
4. `bash scripts/verify.sh` GREEN.

### Required planning refinement


Specify cold snapshot delivery, generation monotonicity, revocation and reconnect behavior
before code. Test DP restart with CP alive, CP outage with DP routing, stale-generation replay,
and explicit h2 negotiation. A startup-only push or a manually restarted CP is not recovery.
Any accepted residue requires explicit maintainer disposition; it is not the default plan.

## Out-of-scope

- T130's landed fix (this rides on it, does not revisit it).
- The T123/T124 product fixes (separate, behind the T131 smoke test).

T147 migration dependency: T172 reconciles HTTP CONNECT contracts and consumer acceptance;
T173 implements refusal with preserved authenticated SOCKS coverage and deployed evidence.
Both must complete before this consumer runs; T147 planning completion alone is insufficient.
