# T156 — constitution strengthening and dependency reconciliation

User authorization: “make the constitution stronger and resolve the weak points … then adjust
…the implementation plan … before we start implementation” (working session, 2026-09-12).
This authorizes the normative/document work. It does not authorize runtime privacy exceptions.

## Constitution Check

This is an explicit pre-release amendment, reviewed against both the old and proposed text.
No runtime conformance is claimed. The prior constitution and amendment history are preserved
verbatim in `.specify/memory/constitution-history.md`. The active Governance section supersedes
contradictory pre-release procedure notes. Amendment review includes codereview and independent
redteam, not a self-issued approval from the author.

| Evaluated weakness | Decision | Compatibility / implementation |
|---|---|---|
| C01 namespaces/tunnels | Retain actual proxy loopback/tunnel binds and add tunnel-loss requirements. No wildcard exception. | T134, children, T123/T124/T155. |
| C02 outbound scope | Exhaustive actor matrix; bounded sidecar maintenance and separate explicitly invoked updater. | These are named permissions, not typo fixes. DP/CP internet access remains prohibited. |
| C03 protocol scope | Bounded proxy negotiation and management TLS permitted separately from opaque destination traffic. | Reviewed semantic clarification; T147 must not infer first party by payload inspection. |
| C04 authority/recovery | Enforced CP capabilities; valid state survives outages, undelivered revocation pending, stale backup cannot silently reauthorize. | T138/T132/T159. CP-outage stale-authority limit explicitly disclosed. |
| C05 isolation | Device/profile/site partition, deterministic bounded identity, reject missing context, no unsupported ingress exception. | Stronger than current raw-site username; T136/T147 transition both sides. |
| C06 operational records | Retain aggregate-only policy with fixed categories/retention; remove per-event journal target. | Choose conformance over an administrative exception; T152 migrates old data/writers. |
| C07 fail-closed/browser | No automatic Direct/system route fallback; preserve honest external-profile precondition. | T157 actual browser outcome; T150/T151 truthful UI. |
| C08 evidence | Strictest category wins; red/green evidence; required skips remain pending; atomic regression/fix work. | T139/T144 and workflow, no runtime test invented for docs. |
| C09 review quality | Bind scope/snapshot/evidence/reviewer capability, cumulative and impact-triggered human review. | T155/T078/T079 remain pending. |
| C10 governance | One active pre-release procedure; acceptance cannot waive principles; impact-based amendment review. | Historical approvals remain historical; no new finding acceptance. |
| C11 supply chain | Artifact-appropriate identities and verification, deliberate promotion. | T140/T141/T145/T081. |
| C12 over-specific text | Keep privacy/scope normative; current toolchain/UI pins remain binding in architecture/build contracts. | No dependency/version upgrade or removed review obligation. |
| Additional: counter polling | Only completed immutable buckets may leave private memory. | T158 plus T149 totals. |
| Additional: stale auth / snapshot acknowledgment | No automatic old-content promotion or acknowledged revocation rollback across supported crash/restart. | T159 followed by T132. |
| Additional: planning notes non-binding | Move required follow-up/consumer closure into Acceptance. | Actual metadata graph, not prose-only order. |

## Alternatives and protection deltas

A container wildcard exemption was rejected because host publication alone does not establish
listener authority or egress confinement. T134 still compares conforming designs; no new topology
is selected without evidence. Detailed admin auditing was rejected in favor of completed-hour
aggregates. This reduces forensic detail and requires legacy-log cleanup, without a browsing-data
exception. Automatic auth expiry during CP outage was rejected because it breaks the explicit
survival goal: valid installed authority persists, and undelivered revocations stay visibly pending.
Automatically renumbering restored stale credential content was rejected; explicit operator
recovery carries that risk decision. Public certificate validity and key possession remain distinct.

The actor/traffic and negotiation allowances are genuine scope decisions and are labelled as such.
They are constrained to the product's own control exchanges, underlying route protocol maintenance
and explicitly authorized retrieval. They cannot authorize proxy payload parsing, telemetry or a
compromised CP's arbitrary public/sidecar access. No new runtime authority is delivered in this diff.

## Execution and verification

The required fresh planning outline is `specs/.handoffs/T156-OUTLINE.md` (ignored session state).
Document changes are checked for consistent normative boundaries, valid ticket graph/queue,
unchanged completed ticket history, live-vs-target claims and synchronized reviewer mirrors.
The task budget is 128 total touched paths, including specs, new files and durable review/delivery
evidence. The initial 88 source inputs are the explicit amendment scope,
not a routine implementation ticket. Production code/config/tests are unchanged.

Run scripts/verify.sh before formal review, then preserve a scoped pre-turn diff and a manifest
hashing all changed inputs, including untracked documents. Independent reviewers receive the
snapshot, ticket acceptance and mechanically produced reports without the author's rationale.
Both verdicts bind the exact manifest. Preserve actual gate limitations, not a fabricated full live
pass. T156 remains in its normal lifecycle until reviewed delivery; the runtime queue is gated by it.
