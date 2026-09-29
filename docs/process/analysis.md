# Analysis gate

## Why this step exists

`scripts/lint-ticket.py` and the clarity reviewer check that a ticket is
*well-formed* — acceptance runnable, `spec_refs` resolve, budget plausible.
They do **not** check that the acceptance is *true to the code*. A ticket can
pass clarity with a factually wrong acceptance — naming a class that doesn't
exist, missing a load-bearing file, asserting a property no test catches.

That isn't sloppiness; it's a missing step. Analysis is that step. It runs at
`scripts/run-task.sh <id>`'s START phase, **before the agent writes any
code**, so the agent grounds the implementation on truth rather than on
ticket prose.

It is adapted from zecsite's `docs/process/analysis.md` (the residue
concept) and adapted to stargate's Constitution — the residue list is
exactly what `stargate-redteam` exists to hunt, and the must-hold list is
where Constitution principles land as concrete, ticket-level properties
rather than 23 KB of prose.

## When it runs

- **Required** when `privacy_critical: true` OR `complexity: high`.
- **Quick pass** otherwise (a fast read of the cited spec section and the
  relevant code paths; no formal property map recorded in the ticket body).

`scripts/run-task.sh` includes the analyze step in its START handoff prompt
and gates the depth on the ticket's `privacy_critical` / `complexity` flags.

## The payload — a property map

Per-ticket analysis produces three lists. They are recorded in the ticket's
§Analysis section when the step is required (low-complexity, non-privacy
tickets skip the section entirely).

### 1. Must hold

The properties the change must satisfy, at invariant altitude. Not
implementation detail — "which file and which line" is decided right before
coding, not here.

For `privacy_critical: true` tasks, this is where Constitution principles
land as concrete properties:

- **Principle I (dumb router):** "every `bind(2)` call is preceded by the
  loopback check", "no payload inspection in the request path", "no per-request
  log line at finer resolution than the aggregate counter bucket".
- **Principle III (no outbound except routed request):** "the data plane opens
  no outbound socket except to the configured sidecar", "no DNS resolution of
  destination hostnames in the data plane".
- **Principle VII (tests-first for privacy-critical paths):** "every
  must-hold property above has a named test asserting it".
- **Principle VIII (adversarial review):** "the residue list (below) is
  non-empty and the redteam scope matches it".

For non-privacy tasks, must-hold is usually one or two lines ("file compiles
under the Maven reactor", "license header present").

### 2. Gated

Which of the must-hold does `scripts/verify.sh` already catch **fail-closed**?

- `go vet`, `staticcheck`, `gosec` catch a class of data-plane correctness and
  security properties.
- The contract tests under `tests/contract/` catch the literal byte-shape and
  behavioural contracts (`torrc` rendering, SOCKS5 byte sequences, proto
  schema conformance).
- (Future) Error Prone + NullAway catch nullness-contract violations on the
  control plane (ticket T081).
- The license-header check catches missing SPDX headers.

Gated properties need **no standing human vigilance** — a green verify.sh is
the proof. Listing them here is what shrinks the residue list to its
essential items.

### 3. Residue

The properties **no gate catches**. This list is the whole point of the step.

Examples of residue on stargate:

- "No outbound `net.Dial` / `http.Get` to non-`tor:9050` destinations in the
  data-plane source tree." — no static check enforces this; only
  `tests/integration/egress_consensus_test.go` (T034f) catches it at runtime,
  and that test runs at release cadence, not PR cadence.
- "No destination hostname in any log line." — the log-allowlist contract test
  (T025a) catches this for the explicit allowlist, but a new log line added
  mid-implementation can slip past unless the developer remembers to extend
  the allowlist test.
- "The `docker-socket-proxy` lockdown (`POST=0`, `EVENTS=1`, `CONTAINERS=1`)
  actually holds." — the contract test T019c proves it at compose-up time, but
  a Dockerfile or compose edit can regress it silently between contract-test
  runs.

Each residue item must map to a named test or guard in §Acceptance, or — if
you can write the missing check — **promote** residue into the gated set by
writing the check. Promoting residue shrinks the list every future ticket
inherits. The residue list *left over* is what `stargate-redteam` and the
reviewer focus on.

## What the residue drives

- **Tests.** Every residue item gets a named test or guard added in this
  ticket's §Acceptance — prefer promoting residue into the gated set; the
  residue left over is what redteam and review focus on.
- **Redteam scope.** Residue helps target the independent adversarial pass.
  Every `privacy_critical: true` ticket requires redteam before commit,
  including when the author believes the residue list is empty. The reviewer
  challenges that completeness claim. It is not a gate-skipping signal.
- **Autonomy.** The root follows the driver through codereview and, when
  privacy-critical, independent redteam. Both approvals are required; rework
  and escalation follow the shared review-loop policy.

## Where it lives, who does it

- The **proposed / corrected acceptance and flags** go into the ticket as
  normal — analysis can rewrite the acceptance it was handed *and* fill one
  that was left blank. A blank or underspecified ticket is **not** a stop:
  derive the acceptance and `spec_refs` from ground truth and propose them.
  Disagreement with the ticket-as-written is equally a *finding*: re-derive
  from ground truth (the `refine` path, before any code).
- For `complexity: high` or `privacy_critical: true`, record the **property
  map** in the ticket's §Analysis section — it is the durable record of *why*
  the acceptance is what it is. Low, non-privacy tickets skip it.
- The **ticket's developer** (the main conversation, or its one delegated
  developer subagent; workflow.md step 3) does the analysis — you hold the
  context. Fan out a read-only `Explore` subagent for the ground-truth survey
  when breadth helps, but the judgment and the property map are yours.

## Output shape

When analysis is required, the ticket's §Analysis section is filled with the
three-list structure, for example:

```markdown
## Analysis

- **Must hold:**
  - The bind check rejects every non-loopback IP literal (FR-010).
  - The check runs BEFORE any listener opens (T050 startup sequence).
  - The check operates on parsed IP literals, never DNS names (Principle III).
- **Gated:**
  - `go vet` + `staticcheck` cover the syntactic surface.
  - Contract test `tests/contract/control-grpc/transport_test.go` (T022) gates
    the socket topology separately.
  - License-header check gates the SPDX header.
- **Residue:**
  - No assertion that malformed input (empty string, garbage bytes) is
    rejected. Add `bind/check_test.go` case (e) — promote to gated.
  - No assertion that DNS names are rejected (the check must operate on parsed
    IPs only, so a hostname smuggled past must fail). Add
    `bind/check_test.go` case (d) — promote to gated.
```

The two residue items in the example each map to a test case the ticket
*adds* — promoting them into the gated set on landing. After the ticket
lands, future tickets touching the bind check inherit an empty residue for
those properties.

## Source-of-truth rule

The contract lives in code + tests + spec + Constitution, not in ticket
prose. Tickets are briefs that point at the spec; analysis grounds them in
the code. Do not re-state spec content inside tickets; do not police
ticket-internal consistency of paraphrased spec.
