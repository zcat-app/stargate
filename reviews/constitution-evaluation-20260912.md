# Constitution weak-point evaluation — 2026-09-12

The core principles should remain. The main weakness is that strong privacy goals are mixed
with underspecified boundaries, concrete implementation choices and inconsistent governance
notes. That gives implementers room to satisfy a narrow reading while missing the protection.
The remedy is a precise, testable contract—not constitutional permission for existing hacks.

This is a document evaluation, not an amendment, approval of residual risk or a new runtime
security audit. Sources are the [constitution](../.specify/memory/constitution.md), current
[threat model](../THREAT-MODEL.md), feature contracts and the
[foundation audit](redteam-20260912-677960b.md). Implementation examples below use that
preserved audit evidence; no new live behavior was tested here. Priorities indicate the order
in which to resolve wording and decisions, not new exploit severity ratings.

## Resolve before affected foundation designs

### C01 — The deployment rule lacks a namespace and lifecycle model

**Source:** Deployment Model, constitution lines 410–424.

“All bindings on 127.0.0.1” does not distinguish host publication, the DP listener, sidecar
listeners or separate container network namespaces. The final invariant checks for a tunnel
interface “present in the same compose stack,” whereas the LAN/VPS descriptions require
binding *only* to that tunnel. Presence alone is a weaker condition than exclusive ingress.
The rule also specifies startup refusal without saying what happens if the tunnel disappears.

**Risk:** a container label, environment flag or unrelated tunnel becomes a substitute for
actual reachability control. T125 demonstrates that danger; it does not prove that the original
privacy requirement is inappropriate. Nor does host-loopback publication alone prove the
container's other interfaces are safe.

**Recommendation:** T134 must first test compliant designs under the current rule. Specify
which processes/listeners/namespaces the protection covers, the permitted client ingress,
tunnel-loss behavior, and separate ingress from egress restrictions. Cover IPv4 and IPv6 if
supported, and assert refusal for unsupported configurations. Merely declaring a container
exception would materially change the rule and requires amendment, not a “clarification.”

**Owner:** T134 and its implementation children; T155 validates the resulting boundary.

### C02 — “No outbound connections” does not identify the actor or traffic class

**Source:** Principle III, lines 246–249; update flow, lines 262–272.

“Stargate” can mean the DP, CP, entire sidecar stack or even build/release tooling. The literal
whole-stack reading leaves no stated allowance for autonomous anonymity-network bootstrap,
while local management IPC and deliberately initiated updates also need classification.
“Local-only” does not distinguish same host from a Compose network or a remote tunnel client.

**Risk:** either ordinary stack operation is deemed unconstitutional, or an implementation
silently exempts all sidecar/management traffic and defeats the intended egress restriction.
The audit's no-masquerade evidence gap makes this ambiguity consequential.

**Recommendation:** define a small actor/traffic matrix: routed destination traffic, internal
control traffic, underlying anonymity-network maintenance, explicitly initiated maintenance,
and prohibited telemetry/update polling. State who may originate each class and through which
boundary. This is a policy decision where exceptions add permission; do not silently authorize
background update checks or unrestricted DP/CP internet access.

**Owner:** T134 for current topology. Any wider update/route allowance needs a separate proposal
before the relevant future feature; T134 cannot approve it by implication.

### C03 — The dumb-router rule does not separate tunnel contents from proxy control

**Source:** Principle I, lines 164–173; Principle II, lines 200–204;
[wire-auth contract](../specs/001-tor-route/contracts/wire-auth.md) and
[SOCKS/CONNECT contract](../specs/001-tor-route/contracts/socks5-auth.md).

Principle I explicitly permits CONNECT parsing but forbids inspection of request headers
without qualification. The CONNECT contract requires proxy bearer authentication. The same
principle forbids TLS termination “for any traffic class,” while the DP terminates mutually
authenticated TLS for its own inter-plane service under the wire-auth contract.

**Risk:** the literal rule condemns control-protocol work, while an unlimited “transport
requires” exception could justify payload inspection.

**Recommendation:** distinguish proxied application bytes, proxy negotiation/authentication,
and management IPC. Enumerate narrowly allowed control parsing and generated failure responses;
retain the ban on inspecting application headers/payloads or terminating tunneled application
TLS. Treat any newly permitted parsing as a semantic change until its scope is explicitly
reviewed. Do not resolve this by removing bearer authentication or IPC authentication.

**Owner:** T147 must account for this boundary in its CONNECT recommendation. A shared Principle
I clarification needs its own reviewed proposal if required before implementation.

### C04 — Availability, revocation and control-plane authority need explicit limits

**Source:** Principle II, lines 189–208; auth/revocation scope, lines 432–435.

“Continue routing” does not distinguish established streams, new authenticated requests,
CP outage after initialization, or a cold DP restart with no snapshot. It does not say when
revocation takes effect while the CP is unreachable. The rationale says management compromise
cannot corrupt routing decisions, but the CP is also assigned sidecar lifecycle authority.
Separate processes and authenticated IPC alone do not specify those capabilities.

**Risk:** an implementation can preserve connections yet leave restart authentication dead,
or give a compromised CP a full Tor cookie while claiming it is merely advisory.

**Recommendation:** define the survival matrix and accepted stale-auth window explicitly;
separate route selection, admission, lifecycle availability and observable sidecar information.
Require capability boundaries for the claimed compromise resistance. Do not promise routing
through a deliberately stopped sidecar, or claim that lifecycle authority is read-only.

**Owner:** T132 (recovery), T138 (authority), T135/T148 (peer identity), then T155.

### C05 — First-party isolation mixes identity definitions and supported ingress

**Source:** Principle III, lines 239–242; audit T136/T147 findings.

The requirement moves between “first-party domain” and “origin” without defining their
relationship. It explains only the extension's username mechanism although the proxy also
supports CONNECT. It omits multi-device/profile partitioning, missing identity, opaque contexts,
and public/private suffix handling. A shared suffix or target hostname is not a specification
of the initiating first party.

**Risk:** a two-label approximation or an ingress with no identity can pass a superficial
“username forwarded” check while failing the intended isolation. The constitutional guarantee
must cover the declared supported surface, not just the happy-path client.

**Recommendation:** define the isolation unit, supported identity sources, device/profile
scope and missing-context behavior. Phrase the measurable property as preventing circuit
sharing across distinct defined isolation keys; avoid implying protection against other
correlation channels. Decide whether clear first-party labels are required or an opaque,
consistent partition identifier is permitted. That latter choice needs design review, not an
incidental refactor. Refuse unsupported ingress rather than silently replace first-party
identity with destination identity.

**Owner:** T136, T147 and their downstream tests, including T126 and T155.

### C06 — Aggregate-only logging conflicts with operational audit responsibilities

**Source:** Principle II, lines 193–194; Principle III, lines 243–245; audit T152 finding.

The constitution assigns audit logging to the CP but allows logs containing only hourly
aggregate counters. Existing lower-level contracts require timestamped administrative/lifecycle
rows. These are distinct from browsing logs, but the constitution grants no exception.

**Recommendation:** first evaluate a design that meets the current literal restriction. If
non-aggregate operational auditing is necessary, propose the exact event/field allowlist,
retention, access controls and prohibition on linkage to browsing activity. That would be a
substantive policy amendment, even if the current code already emits those events. “Operational
logs” alone is too broad an exception. Do not infer browsing leakage from timestamps alone.

**Owner:** T152. Existing behavior and SECURITY-DECISIONS entries cannot override the constitution.

### C07 — Fail-closed needs an observable network outcome; onboarding still drifts

**Source:** Principle III, lines 220–238; onboarding scope, lines 438–440.

The amended principle carefully limits runtime API enforcement, but “refuses non-Direct
routing” can still be misread as permission to fall back to Direct. The onboarding bullet
still promises an extension configuration audit covering DoH/QUIC/foreign extensions, despite
the principle assigning some checks out of band. The rationale that properties remain true
under configuration drift is broader than the explicitly accepted browser-profile residue.

**Recommendation:** state that failure to satisfy a selected protected route must not silently
send that request through Direct or another route; make cancellation/no-network behavior the
observable test. Keep deliberate Direct selection separate. Align onboarding and explanatory
prose with the approved T091 boundary, identifying the tested profile/version and when evidence
expires. Do not broaden runtime API claims or silently rescind the documented residue.

**Owner:** T155's live browser probe, T151 and release T034a; any confirmed implementation gap
gets a focused child ticket. The audit did not prove actual fallback packets on the wire.

## Strengthen assurance and governance

### C08 — Tests-first is necessary but does not establish independent evidence

**Source:** Principle VII, lines 335–355; AI workflow; foundation audit baseline.

The table can be misread to classify security-sensitive Compose/scripts as mere smoke-test
work. “Before implementation lands” is also weaker than demonstrable failing-before-fix
execution, although the surrounding tests-first language and canonical workflow are stronger.
The constitution does not itself define coverage floors, positive controls, skipped mandatory
checks or retained evidence. Those gaps enabled a green suite alongside serious missing properties.

**Recommendation:** clarify that the strictest applicable category wins regardless of file
extension. Keep detailed mechanics in workflow: spec-derived falsifier, red/green snapshot
references, required-suite inventory, environment-aware evidence and no SKIP-as-PASS. For old
code, honestly record retrospective regression evidence. Resolve standalone red-test-ticket
versus green-before-merge sequencing in workflow; do not weaken either requirement to make the
scheduler advance.

**Owner:** T139/T144/T155. This largely needs workflow enforcement, not a weaker constitution.

### C09 — Review names are specified more precisely than review quality

**Source:** Principle VIII, lines 362–387; canonical review loop and AGENTS model-drift note.

Two named subagents and fresh context do not by themselves establish reviewer capability,
independence from implementation, actual execution evidence or adequate coverage. The external
human review requirement is valuable, but the constitutional wording does not bind its scope
and closure evidence to an exact release candidate. New high-risk changes within a major
release series can also deserve external review without waiting for the next major number.

**Recommendation:** retain independent review and the pre-v1 human gate. Define durable snapshot,
reviewer/tool identity, scope, evidence limitations and finding closure requirements in workflow.
Document capability limitations honestly; a configured reviewer name is not assurance. Consider
risk-triggered external review as a strengthening proposal, without turning a particular model
vendor into constitutional authority. T133's per-ticket review is an additional workflow gate,
not inconsistent with milestone review.

**Owner:** T154/T155/T078/T079; broader assurance changes need a scoped proposal.

### C10 — Risk acceptance and amendment authority need a sharper boundary

**Source:** Principle VIII, lines 376–379; Governance; pre-release comment log.

VIII permits acceptance of Blocker/Major findings, but does not locally state that accepting a
finding cannot waive a constitutional invariant. Governance establishes that precedence, yet
an agent reading only VIII could treat a security-decision entry as permission. The historical
header also contains different governance activation events: first public remote versus first
public release, plus differing PR/comment-window descriptions. Some are explicitly superseded;
the active pre-release procedure still requires readers to reconstruct it from comments.

Only I/III/V amendments explicitly require redteam, although plane authority, deployment,
supply-chain controls and review discipline can change privacy protection materially too.

**Recommendation:** publish one unambiguous active pre-release procedure while preserving the
historical log. Say explicitly that risk acceptance cannot waive a principle; changes to the
principle require amendment. Consider security-impact-based review triggers for amendments
wherever located, including Deployment Model. Require alternatives, protection delta, evidence
and downstream effects in an amendment proposal. A failed test or model's workaround is not
amendment rationale on its own.

**Owner:** separate governance proposal, not T134 or this evaluation. No approval is implied here.

### C11 — Supply-chain guarantees are broader than their specified mechanism

**Source:** Principles IV and VI, lines 255–272 and 304–325.

“All external components” cannot be described solely by container image digests: source
packages, Maven dependencies, downloaded tools, Actions and extension archives have different
identities. Digest pinning, authenticated provenance and reproducibility are distinct properties.
The update flow implies dashboard discovery without reconciling outbound monitoring restrictions.

**Recommendation:** preserve immutable inputs and manual promotion as invariants, then require
artifact-appropriate content identities and integrity verification in the build/release
contract. Define which component discovers updates and under which authorized network policy.
Do not claim a pinned container proves all downloaded build inputs are pinned or trustworthy.

**Owner:** T140/T141/T145/T081 for existing work; broader policy clarification with C02.

### C12 — The constitution contains too much replaceable implementation detail

**Source:** Tech Stack, versioned browser API names in III, build tooling in VI, v1 scope.

The document combines durable privacy invariants with framework/tool names, UI choices,
packaging commands, reserved ports and a release roadmap. That increases amendment pressure
for ordinary engineering changes and makes genuinely important guarantee changes harder to spot.
There is small internal scope drift too: V enumerates VPN as a route while v1 scope lists
Tor/I2P/Nym/Direct and deployment treats tunnels separately.

**Recommendation:** retain normative guarantees, supported protection scope and approval
boundaries in the constitution; consider moving replaceable mechanisms and version pins into
explicitly subordinate architecture/release contracts. Moving a requirement must not silently
remove its authority: approve what remains binding and who can change it. Do not bundle this
large editorial restructuring with urgent privacy repairs or T125 remediation.

**Owner:** later document-structure proposal. This is lower priority than C01–C07.

## Recommended decision order

1. Continue T154/T139 and the definite T135–T137 fixes. None needs permission to relax a principle.
2. Feed C01–C07 into existing design/recovery tickets before their affected implementation.
   Where current guarantees cannot be met, stop that surface and present concrete alternatives.
3. Draft separate, small proposals only where necessary: boundary clarification, operational
   logging policy, and active governance. Label each as clarification, strengthening or changed
   permission based on its actual effect; do not hide semantic changes as wording fixes.
4. Use T155 to validate the repaired implementation against the resulting authoritative text.
   T078/T079 remain final cumulative gates. Leave broad document restructuring until later.

No constitution amendment, risk acceptance or additional implementation ticket was made in this
evaluation. Existing owners cover the immediate audited surfaces; proposals without an existing
owner must receive a dedicated ticket before non-trivial changes. The implementation order from
[the remaining plan](../specs/001-tor-route/remaining-implementation-plan.md) remains appropriate.
