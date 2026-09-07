---
id: T127
title: 'Correct T058 comment: DP dials upstream with UNAME only, no token'
status: done
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T121 convention); T061 round-1 codereview RECOMMENDED-FOLLOW-UP
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: []
parallel: true
files_budget: 3   # raw-diff-path counting: 1 comment-only test-file edit + this ticket + STATUS regen (T116 convention)
privacy_critical: false   # comment-only doc fix in a test file; no executable line changes
complexity: low
risk: low
round_cap: 2
remediates: T058
spec_refs:
   - specs/001-tor-route/spec.md#FR-002   # inbound PASSWD = device bearer token (extension → DP)
   - specs/001-tor-route/spec.md#FR-006   # DP-side token verification (HMAC-SHA-256 + pepper)
   - specs/001-tor-route/spec.md#FR-007   # DP forwards the SOCKS5 USERNAME unchanged upstream — and ONLY the username
decision_refs:
   - data-plane/internal/forward/tor.go dialUpstream — `proxy.Auth{User: string(uname)}` with empty password (PLEN=0); the inbound PASSWD is "auth-layer material that is never re-sent upstream"
   - tests/integration/stream_isolation_test.go — T059's comment states the correct shape ("never re-sent upstream")
   - tests/integration/circuit_isolation_corpus_test.go — T061's comment states the correct shape
reviews: { round: 1, date: 2026-09-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T127: Correct T058 comment: DP dials upstream with UNAME only, no token

## Context

Hand-filed 2026-09-07 from T061's round-1 codereview RECOMMENDED-FOLLOW-UP.
`tests/contract/torrc/isolate_socks_auth_effect_test.go` (T058, done) carries
a stale factual claim in its auth-identity constants block (lines ~123–125):

> Fixed PASSWD so UNAME is the only isolation differentiator. In
> production the DP forwards PASSWD = bearer token; against tor
> directly it is simply the second half of the SOCKS auth identity.

The production data plane does NOT forward the bearer token upstream:
`forward/tor.go` `dialUpstream` sends the inbound SOCKS5 username verbatim
with an empty password (PLEN=0) — "the inbound PASSWD is the bearer token,
auth-layer material that is never re-sent upstream" (FR-002 pins the inbound
password = token; FR-006 pins DP-side verification; FR-007 pins username-only
passthrough). T058's comment contradicts the implementation, the spec, and
the correct comments in T059/T061's integration tests. A reader calibrating
the upstream auth identity from T058's comment would expect the token on the
wire to tor; it is never there.

The test's BEHAVIOR is unaffected: PASSWD is a fixed constant in both T058's
harness and production (where it is empty), so UNAME remains the only varying
isolation axis either way. This is a comment-only correction.

## Analysis

*(Quick pass — comment-only doc fix in a test file; no executable lines.)*

## Acceptance

1. The constants-block comment in
   `tests/contract/torrc/isolate_socks_auth_effect_test.go` states the
   production shape: the DP dials the sidecar with the inbound UNAME
   verbatim and an EMPTY password (PLEN=0) — the bearer token is validated
   at the data plane and never re-sent upstream (FR-002/FR-006/FR-007;
   `forward/tor.go` `dialUpstream` as the code anchor).
2. Zero executable-line changes: `git diff` shows only comment lines.
3. `bash scripts/verify.sh` GREEN; the torrc suite remains compile-checked
   (`go vet -tags docker` accounting per T076).

## Out-of-scope

- Any change to T058's assertions, deadlines, identities, or PASSWD value.
- SECURITY-DECISIONS.md — the 2026-09-07 T058 entry is accurate as written.
- The same-named (correct) comments in T059/T061's files.

## Notes

Hand-filed 2026-09-07. The wrong claim was also present in SECURITY-DECISIONS
2026-09-07 (T061 amendment entry) as an FR-citation erratum — corrected there
by a same-day record-only supersession entry, not by this ticket.

Constitution check: comment-only, no privacy surface touched; Principle VII
unaffected.
