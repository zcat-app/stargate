---
id: "T138"
title: "Define an enforced Tor observation boundary"
status: in-review
created: "2026-09-12"
last_updated: 2026-09-20
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T094a", "T139", "T134", "T156"]
parallel: false
files_budget: 10
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md", "specs/001-tor-route/contracts/foundation-boundaries.md", "THREAT-MODEL.md"]
decision_refs: []
remediates: "T094a"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T138: Define an enforced Tor observation boundary

## Context

Existing finding 20260727-001 was independently rediscovered: CP holds the full Tor cookie, so its Java command allowlist cannot constrain a compromised CP.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

The property map is: the CP must have no Tor cookie, cookie group or raw
`tor:9051` path; a separate observer must expose only bounded finite health;
raw Tor replies and dangerous commands must never cross into CP consumers; and
observer failure must remain advisory without DP fallback. Existing
`SidecarMonitor` tests gate only its own command list; the CP still has the
cookie and raw path, so a compromised CP can bypass it.

## Acceptance

1. Map the CP credential and reachable Tor commands against Constitution II/III and the threat model, distinguishing disclosed residue from enforced restrictions.
2. Compare removal of direct CP control credentials with an independently enforced narrow observer; specify sanitized allowed outputs and failure behavior.
3. Define negative acceptance probes from CP production context for stream observation and configuration commands, plus a positive sanitized-health probe. Do not issue dangerous commands against an operator stack.
4. Deliver a design for review and an explicit unresolved-decision list before production changes; no risk acceptance or constitution amendment is authorized here.
5. Add the concrete follow-ups `T164` (tests-first observer implementation) and `T165` (deployment/consumer evidence), each with `remediates`, spec/contract references and measurable closure criteria. Add both to `T155` and wire the affected clean-host/healthcheck consumers (`T123`/`T124`) to wait for them.

### Design comparison and decision record

| Design | CP authority | Health/event result | Decision |
|---|---|---|---|
| Current direct cookie + Java allowlist | CP owns the cookie and raw `tor:9051`; Tor has no per-command ACL | Existing health/events work, but a compromised CP bypasses the Java list | Rejected; this is the disclosed finding. |
| Remove the CP credential and raw observation | CP has no Tor authority | No Tor health observation or lifecycle events | Rejected for v1 because it breaks the existing advisory health/event contract; it remains safer than the current residue but is incomplete. |
| Dedicated narrow observer | Observer alone owns the cookie/raw session; CP reaches only its authenticated fixed health RPC | Observer maps health to finite tokens; CP retains the fixed event vocabulary but emits only substantiated events | Selected; T164 implements it after T162's fabrics and T165 proves deployment closure. |

The following decisions are explicit. Items marked unresolved are release-blocking
and have an owner; they are not permission to implement the current direct path:

- **CP-facing authority (decided, T164):** use versioned mutually authenticated
  IPC over the CP-only Unix-socket fabric. The observer authenticates the CP
  peer, accepts only a bounded `HEALTH` request, and returns only
  `READY`/`NOT_READY`/`UNAVAILABLE`. Filesystem group ownership is defense in
  depth, not the sole caller-authentication mechanism.
- **Observer Tor authority (decided, T164):** only the observer has the cookie
  and Tor-facing socket; its fixed sequence is `AUTHENTICATE`,
  `GETINFO status/bootstrap-phase`, `QUIT`. No raw reply crosses the boundary.
- **Protocol bounds (decided, T164):** after mutual peer authentication, one
  connection carries exactly one ASCII `HEALTH/1\n` request (9 bytes) followed
  by client write-EOF. The only replies are `READY/1\n` (8 bytes),
  `NOT_READY/1\n` (12 bytes), and `UNAVAILABLE/1\n` (14 bytes), followed by
  close. Extra bytes, fields, CR/NUL, missing EOF, unknown versions, and
  unauthenticated callers receive no health token. The request/EOF deadline
  is 1 second; the observer's entire Tor connect/auth/query/reply budget is
  4 seconds; the CP's whole observer call is capped at 6 seconds. At most one
  Tor query runs at a time, with no waiting queue; excess calls receive the
  fixed `UNAVAILABLE/1\n` token. The Tor-facing parser caps each reply line
  at 8 KiB, each reply at 64 lines and 8 KiB total, within the same 4-second
  budget. T164 tests these limits before implementation.
- **Health and event meaning (decided, T164):** `READY` means an authenticated
  Tor control reply with bootstrap `PROGRESS=100`; `NOT_READY` means a valid
  authenticated reply with progress below 100. Tor dial/auth failure, malformed
  or oversized reply, and timeout yield `UNAVAILABLE`. Observer transport,
  authentication, version or deadline failure is locally treated by CP as
  `UNAVAILABLE`, with no raw detail. The first valid `READY`/`NOT_READY`
  sample emits `STARTED` once. A transition into `READY` from any other state
  emits `HEALTHY`; a transition from `READY` to `NOT_READY` or `UNAVAILABLE`
  emits `UNHEALTHY`/`healthcheck_fail` once. Repeated samples and transitions
  between `NOT_READY` and `UNAVAILABLE` emit nothing. An unavailable observer
  cannot prove Tor exited or restarted, so this health channel emits no
  `STOPPED`, `CRASHED` or `RESTARTED` claims. T164 must reconcile the emitted subset in
  `contracts/control-grpc.md` and its tests before replacing `SidecarMonitor`;
  the existing event kind/detail vocabulary stays closed. All these events
  remain advisory to DP admission and route selection.
- **Packaging and identity (unresolved, T164):** choose the implementation
  language and Stargate-owned image, then pin its immutable digest and verified
  provenance before deployment. A mutable tag or unverified local build cannot
  close this ticket.
- **Profile mediation (unresolved, T165):** pin the Local/LAN/VPS socket,
  peer-credential and AppArmor/network rules, with a positive health control
  and negative raw-command/non-arrival controls for each supported profile.
- **Lifecycle control (unresolved, future governed spec):** no lifecycle
  command is exposed by the health observer. Any future start/stop/reload
  capability requires a separate contract, credential and review.

### Concrete safe probe matrix

T164/T165 execute these cases only against disposable fake observer/Tor
endpoints or the disposable clean-host Local deployment; no dangerous command
is sent to an operator stack. The CP production identity is UID 5101 with no
Tor-cookie group.

| CP-context input | Fixture/control | Required result |
|---|---|---|
| Read `/run/tor/control_auth_cookie` and inspect the Tor-cookie group | CP container filesystem and identity | `ENOENT`/no group; no cookie bytes. |
| Connect to `tor:9051` and attempt arbitrary control DNS/TCP | Disposable Tor-control listener records source and commands | CP connect/referral is refused; listener records no CP attempt. |
| `GETINFO stream-status`, `GETINFO circuit-status`, `GETCONF SocksPort` | CP-facing observer socket; fake Tor control log is the non-arrival control | Fixed refusal/close; none reaches fake Tor. |
| `SETCONF SocksPort=9050`, `SETEVENTS STREAM`, `ATTACHSTREAM 1 1` | Same | Fixed refusal/close; no Tor-side command. |
| `ADD_ONION NEW:BEST`, `SIGNAL NEWNYM`, and `COMMAND arbitrary` | Same | Fixed refusal/close; no Tor-side command or raw reply. |
| `HEALTH/1\n` with invalid or absent CP peer authentication | CP-facing observer socket; fake Tor control log is the non-arrival control | Fixed refusal/close; no token, raw reply or Tor-side command. |
| Extra request bytes/fields, unknown version, missing EOF or request timeout | Same | Fixed refusal/close; no health token or Tor-side command. |
| `HEALTH/1\n` with valid peer authentication | Fake Tor returns bootstrap `PROGRESS=100` | Exactly `READY/1\n`; no Tor reply text crosses into CP. |
| `HEALTH/1\n` with valid peer authentication | Fake Tor returns valid bootstrap progress below 100 | Exactly `NOT_READY/1\n`; no false `HEALTHY` event. |
| `HEALTH/1\n` with valid peer authentication | Fake Tor returns malformed/oversized reply, times out, or cannot authenticate/connect | Exactly `UNAVAILABLE/1\n`; no raw detail or false Tor exit/restart event. |
| `HEALTH/1\n` while the observer is down or its reply is malformed/timed out | CP transport fixture | CP treats it as `UNAVAILABLE`; no raw detail or false Tor exit/restart event. |

### Required planning refinement


Completion requires a reviewed recommendation and concrete implementation follow-up tickets with
`remediates`, spec/contract references, a tests-first regression, and measurable closure criteria.
Before marking this investigation done, add every required follow-up to T155 `blocked_by`
and to affected consumers (including deployment, CONNECT tests, or event consumers as applicable).
A recommendation alone does not close the finding. Unresolved authoritative conflicts remain
blocking; this ticket cannot authorize a constitution amendment or accept the risk.

## Out-of-scope

Implementing a new sidecar or relaxing privacy guarantees before the design is settled.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within the T164 implementation ticket rather than as a permanently
red standalone test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

The round-2 escalation was caused by the removed diff-growth rule, not a
reviewer `ESCALATE` verdict. T166 repaired that workflow and its final status
is carried in this candidate. Round 3 addresses the archived round-2 findings.
