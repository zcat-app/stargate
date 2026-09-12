# Stargate Constitution

Stargate is an open-source, multi-protocol privacy-routing proxy. The client chooses
Tor, I2P, Nym or explicitly Direct for each request. This constitution defines binding
privacy properties, trust boundaries and evidence requirements. A feature contract
specifies mechanisms; an implementation or an accepted finding cannot waive a principle.

**Version:** 1.0.0 (pre-release) · **Ratified:** 2026-05-17 · **Amendment:** T156, 2026-09-12.
The maintainer requested this strengthening in the working session. Review and delivery
state is recorded in T156; editing this file does not establish implementation compliance.
The earlier amendment log is preserved in [constitution-history.md](constitution-history.md).
The Governance section below is the sole active procedure; conflicting historical procedure
notes are superseded. No public release or external human review is claimed here.

## Sync Impact Report — T156

- **Scope:** all eight principles, deployment boundaries, scope terminology and governance.
- **Protection retained:** application-byte opacity, no destination DNS in the proxy,
  no Direct fallback, first-party isolation, aggregate-only logs, deliberate updates,
  independent review and the external human review release gate.
- **Strengthening:** capabilities rather than process separation alone; tunnel-loss safety;
  completed-hour metrics publication; explicit client isolation partitions; authenticated
  recovery and revocation semantics; evidence tied to the reviewed candidate; impact-based
  amendment review. T125's wildcard exception is not adopted.
- **Explicit boundary changes:** IPC TLS and narrowly bounded proxy negotiation are allowed
  separately from application traffic. Sidecar-native network maintenance and an isolated,
  explicitly invoked updater are named traffic classes. These are bounded permissions,
  not editorial-only changes or blanket internet access for the DP/CP.
- **Policy decisions:** operational records remain aggregate-only; no timestamped admin-log
  exception. Existing trusted auth state remains usable during CP outage with the revocation
  limitation stated below. Implementation/version pins move to subordinate, reviewed contracts.
- **Downstream:** AGENTS, CONTRIBUTING, workflow/review-loop, architecture, feature spec/plan,
  threat model, data/IPC contracts, reviewer guidance, tickets and planning templates are
  reconciled in T156. Remaining implementation gaps are explicitly tracked, not marked PASS.
- **History:** no constitution version bump before first public release. Review verdicts and
  the amendment's affected-file manifest are retained with the T156 review artifacts.

## Terms and scope

- **Application traffic:** bytes inside an established proxy tunnel, including destination
  TLS and HTTP headers. They remain opaque to Stargate's data plane.
- **Proxy negotiation:** the bounded SOCKS/CONNECT exchange needed to authenticate a client,
  identify its requested destination and isolation partition, and establish or refuse a tunnel.
- **Management traffic:** authenticated IPC, administration and narrow sidecar lifecycle/health
  operations. This is never a channel for application payloads or per-request observations.
- **Proxy services:** the data plane (DP) and control plane (CP). **Stack** additionally includes
  explicitly specified sidecars. A sidecar's privileges do not transfer to the proxy services.
- **Local management:** on-host authenticated IPC or loopback administration; in LAN/VPS mode,
  administration may traverse the configured authenticated tunnel. A container bridge is not
  inherently trusted, and a remote public endpoint is not local management.
- **Direct:** an explicit client route, not an error recovery mechanism. It has no anonymity
  guarantee, but remains subject to proxy authentication, data minimization and DNS boundaries.

## Core Principles

### I. Dumb Router (NON-NEGOTIABLE)

The DP is a transport switchboard. It MUST NOT:

- inspect, modify or log tunneled application payloads or application headers;
- terminate application TLS, interpose a CA, or decrypt the user's destination traffic;
- resolve a destination hostname locally, including through a local resolver, DoH or DoT;
- choose another route, replay a request, or generate replacement application traffic on failure;
- generate cover, decoy, chaff, speculative destination probes or circuit-preheating requests;
- persist request metadata, payloads or isolation identities to disk.

Only bounded proxy negotiation is permitted before the byte pipe begins. Its contract MUST
allowlist fields, parsing limits, authentication/isolation semantics and fixed failure responses.
CONNECT authority and proxy credentials may be parsed; unrelated headers are discarded without
interpretation or forwarding. No application header inspection becomes permissible by naming it
“transport.” Diagnostics and error responses MUST NOT echo destinations, credentials or upstream
text. After tunnel establishment, upstream failure closes the pipe without an injected body.

TLS terminating Stargate's own authenticated IPC or admin endpoint is permitted; it MUST NOT
terminate a destination's TLS session. Protocol authentication never authorizes payload inspection.
Each route listener has exactly one upstream route binding fixed at startup. The client chooses
the route; CP events and per-request content cannot change that binding.

**Why.** Keeping application traffic opaque limits the privacy TCB and prevents a management
or protocol convenience from becoming a new inspection or route-selection mechanism.

### II. Plane Separation

Two primary services have separate lifecycles and privileges: the Go DP owns forwarding;
the Java CP manages configuration, administration and narrowly scoped lifecycle/status functions.
Additional sidecars require explicit capability and network contracts, not extra proxy authority.

The CP MUST NOT participate in request admission or forwarding. A running DP MUST serve new
requests under its last valid auth state and continue existing byte pipes during CP outage,
provided their upstream remains available. Missing/stale/forged status events MUST NOT suppress
an otherwise permitted upstream dial. Authentication failures still deny requests.

| Condition | Required behavior |
|---|---|
| CP unavailable, DP has valid auth state | Continue authenticated admission and forwarding; no per-request CP call. |
| DP restarts with a valid persisted snapshot | Restore the last valid auth generation and fixed route configuration; resume admission independently of CP. |
| No valid snapshot or verifiable auth state | Deny new requests until authenticated state arrives; never start unauthenticated. |
| DP restarts while CP remains up | Automatically reconcile the current durable CP state; restarting CP manually is not recovery. |
| Revocation/update issued while DP unreachable | Report pending delivery, not success. Do not claim effective revocation until DP acknowledges application. |
| Accepted revocation while DP is running | Atomically reject new admissions using revoked credentials. Existing byte pipes may finish; revocation is not a claim to terminate them. |

During a CP outage the retained generation has **no time-based expiry solely because the CP is
unavailable**. Consequently, new revocations cannot take effect until delivered. UI and threat
model MUST disclose this limit; an operator can stop the route to stop access. Automatic state
recovery MUST NOT silently reauthorize credentials from a stale backup: stale generations are
rejected, and an authoritative rollback requires an explicit operator recovery procedure.
Snapshots MUST preserve the last acknowledged state atomically. Corrupt, incompatible or missing
snapshots cannot authorize clients. Host/root rollback of all trusted state is outside this guarantee.

All cross-plane traffic uses versioned, mutually authenticated IPC. Both roles require current
peer authorization on full and resumed handshakes, proof of key possession, and the validity
policy in the wire contract. Identity rotation, reconnect and expiry cannot become auth bypasses.
Established channels need a specified revocation/rotation lifecycle; handshake checks alone do
not claim instantaneous termination of an already authenticated channel.

A compromised CP MUST NOT obtain application payloads, destinations, stream/circuit events,
unrestricted Tor control credentials, arbitrary sidecar commands, or arbitrary engine/host access.
Enforcement MUST be outside the CP's own code/credentials. Permitted lifecycle controls may affect
availability, but cannot silently alter route bindings, disable isolation or choose arbitrary
sidecar configuration. Authenticated control input remains untrusted input at the IPC boundary.

**Why.** Separate processes are insufficient without constrained capabilities and explicit
failure semantics. Availability does not justify unauthenticated routing or silent rollback.

### III. Privacy-Preserving by Construction

Privacy properties have named enforcement mechanisms and documented preconditions.

**Client state.** Routing preferences, per-site memory and history remain client-side. The
proxy MUST NOT persist per-user routing data. Minimal device credentials, verifier generations
and installation keys may persist for authentication/recovery, with ownership and deletion rules;
they MUST NOT be joined to browsing activity. Credentials and routing state MUST NOT be synced
or exported by the extension without a separately specified, explicit user action.

**DNS and route failure.** Destination names pass unresolvable-by-proxy as hostname-form SOCKS5
requests to the selected adapter/sidecar (SOCKS5h). Direct also requires a specified adapter
boundary; it does not permit local destination resolution by DP/CP. Fixed internal service-name
resolution, if needed, MUST be restricted to configured service identities and MUST NOT forward
arbitrary names to an external resolver. IP-literal requests need no lookup and cannot be used
to evade route restrictions. Unsupported protocols/addresses are refused.

A request selected for a protected route MUST be blocked if its hardening, authentication,
isolation or route prerequisites fail. It MUST NOT silently fall back to Direct, system proxy
settings or another route. UI warnings alone are not blocking. Tests MUST observe the network
outcome, including redirects, subresources, retries and startup/reconnect races. An explicit new
user route selection is distinct from automatic fallback. Route indicators MUST state their scope
and MUST NOT imply that an entire tab was protected because one subresource used a protected route.

**Browser precondition.** Non-Direct routes require a tested target-browser profile with DoH,
DoT, WebRTC and HTTP/3/QUIC disabled. DoH/DoT/HTTP-3 are verified out of band at release cadence;
the extension MUST NOT claim runtime access to preferences its supported API cannot expose.
Runtime WebRTC checks and SOCKS5h descriptors remain mandatory. Failure/unknown state of a
required runtime check blocks the protected request. The tested browser/profile versions,
procedure and evidence MUST be recorded; changes affecting those assumptions require revalidation.
Post-verification DoH/DoT/HTTP-3 drift remains the explicitly documented T091 residue, not a claim
of runtime enforcement. Onboarding MUST explain external prerequisites and API limits truthfully.

**Tor isolation.** Distinct isolation partitions MUST NOT share a Tor circuit. A partition
includes the authenticated client/device, browser profile and initiating top-level site. For
DNS sites, the site uses an authoritative public-and-private suffix boundary, never “last two
labels”; for onion services it preserves the complete service identity. Schemes, ports, IP
literals, nested/opaque contexts and navigations have a deterministic, tested contract. A site
is not interchangeable with an origin or with the destination of a subresource. Missing or
untrustworthy initiating context blocks the protected request. Unsupported ingress is refused.
All supported ingress protocols MUST carry the required context; CONNECT has no implicit exception.
The wire contract defines a collision-resistant bounded representation and forwards the Tor
isolation credential intact. Its representation MUST NOT expose bearer secrets to Tor. This
prevents cross-partition circuit sharing; it does not promise protection against every correlation
channel or guarantee that requests within one partition always share exactly one circuit.

**Logs and counters.** All Stargate-generated persistent operational and traffic records are
aggregate counters in fixed buckets of at least one hour. There is no timestamped administrative
journal exception. No destination, URL, header, token/label, client IP, isolation identity,
per-request timestamp, reference ID or arbitrary detail text may enter logs, metrics or crash
reports. Bucketing a timestamp on each event is not aggregation. Exported/persisted counters
contain only completed, immutable buckets: repeated reads cannot reveal changes within an hour.
Current traffic counters remain private volatile state. Finite, current lifecycle/readiness enums
and static redacted command-error responses are allowed; they MUST NOT expose request activity
or become an event-history stream. Operational aggregate categories and retention are allowlisted
in the data contract. Diagnostic stdout/stderr and container logs are included; debug mode cannot
waive the rule. Third-party sidecar diagnostics MUST be suppressed or filtered at a boundary
before Stargate retains/exports them; necessary native protocol state is separately threat-modelled.

**Network origins.** The runtime network permission matrix is exhaustive:

| Actor / traffic | Allowed boundary |
|---|---|
| Browser's routed request | Selected authenticated route; no automatic route downgrade. |
| DP | Request forwarding to fixed configured adapters, and narrow authenticated local IPC; no independent public-network egress. |
| CP / observer | Narrow authenticated local management and specified sanitized health/lifecycle channels; no destination/SOCKS egress or arbitrary internet access. |
| Anonymity-network sidecar | Its own protocol's documented bootstrap/maintenance/peer traffic and routed traffic, limited to that route's TCB. This does not authorize DP/CP probes or extra cover traffic. |
| Direct adapter | Only explicit Direct request traffic and required destination resolution at that adapter, isolated from protected routes. |
| Explicit maintenance helper | Bounded artifact retrieval/verification for an operator-selected install/update; separate from DP/CP, no background polling or unsolicited telemetry. |
| Build/CI dependency tools | Reviewed development/release workflow, outside the deployed runtime; no deployed credentials or user data. |

Telemetry, remote crash reporting, status beacons, external notification services and background
update checks are forbidden in v1. Local management is not a blanket exception for arbitrary
LAN access. Enforce the actor/destination matrix against a compromised application process;
Docker labels, lack of NAT and failure of one TCP probe do not prove an egress boundary.

**Why.** Mechanisms, testable boundaries and honest preconditions limit drift. Accepted residue
must be explicit; neither documentation nor a warning substitutes for an enforceable property.

### IV. Pinned, Tested, Manually Promoted Updates

Every external executable/build input MUST have an immutable, verifiable content identity.
Container images use sha256 digests, never mutable tags alone. Packages, downloaded tools,
Actions, libraries and extension inputs use artifact-appropriate locked identities and integrity
verification before execution. A version string or comment containing a checksum is not verification.
Signatures/provenance authenticate origin; hashes identify content; reproducibility compares builds.
None substitutes for the others or establishes that a maintainer is trustworthy.

An automated repository dependency tracker may propose an update. CI checks the affected
contracts and integrity/reproducibility obligations; a human reviews and promotes it. Deployed
components change only by explicit operator action through local administration. The dashboard
may present locally supplied metadata; retrieval runs only through the bounded maintenance
helper in III. Background installation, background update discovery and automatic digest promotion
are forbidden. Failed verification leaves the current validated installation intact.
Release artifacts MUST correspond to the reviewed source snapshot; post-tag source mutation
cannot silently replace it. Compromised/rolled-back update metadata requires a specified refusal
and recovery policy, not an unchecked downgrade to “last known working.”

**Why.** Updates change the TCB. Both what executes and who deliberately authorized promotion
must remain inspectable.

### V. Honest Threat Model

Every supported deployment mode (Local/LAN/VPS) and route (Direct/Tor/I2P/Nym) has a threat model
stating protections, exclusions, trusted actors, observable information and residual risks.
WireGuard/Tailscale are deployment access tunnels, not an additional v1 routing guarantee.

A protection MUST be identified as a required target, implemented mechanism or verified result;
these are distinct states. Unresolved contradictions and missing/live-skipped evidence remain
visible with owners and release blockers. Neither a completed ticket nor a passing unit test
establishes end-to-end privacy. Do not assert guarantees beyond the underlying network's scope.
UI, onboarding and release notes MUST use the same protection boundaries as the threat model.
Changes affecting these surfaces update the threat model in the same reviewed change.

**Why.** Users need to distinguish what is promised, what is implemented and what was measured.

### VI. Open and Auditable

Stargate is Apache-2.0 open source. Source, build inputs, contracts, governance and decisions
are version controlled and available with each release. Critical code links to its invariant.

Reproducibility tiers remain binding:

- Go data plane: byte-reproducible with pinned toolchain and deterministic build flags.
- Quarkus JVM artifacts: byte-reproducible with pinned JDK/Maven and deterministic packaging.
- Quarkus native image: built from verified bytecode; expected variance is documented in
  BUILD-DIFFS.md. Unexplained differences block promotion.
- Stargate-built sidecars: immutable snapshot/version inputs and byte-stable package manifest;
  authenticated archive/package verification. Image byte equality is best effort; expected
  metadata/post-install variance is documented, not silently ignored.
- Extension: reproducible packaged bytes using pinned inputs and deterministic archive metadata.

Release evidence specifies toolchains, environment, input identities, commands and actual
compared artifacts. An empty comparison or skipped job is not reproducibility. Concrete library,
framework, builder and UI versions live in reviewed architecture/build contracts; they remain
binding there and require deliberate tested updates under IV. Moving a pin does not unpin it.

**Why.** Auditors must connect delivered bytes to the source and inputs actually reviewed.

### VII. Tests-First for Privacy-Critical and Contract Code

The strictest applicable category controls, regardless of language or file extension. DNS,
routing, headers, auth, sidecar/IPC contracts, deployment permissions and privacy-sensitive
infrastructure require spec-derived tests before implementation. A smoke test is insufficient
when a stronger property applies. All AI-generated implementation follows tests-first; other
non-critical human implementation requires tests by review time. Bug fixes require regressions.
Networking tests exercise real sockets and the relevant sidecar boundary, not only mocks.

For a new behavior/fix, preserve a failing result demonstrating the missing property, then its
passing result after implementation. A failure due only to missing tooling is not a falsifier.
Tests that independently prove existing behavior are retrospective evidence, never fabricated
historical tests-first compliance. Pure normative-document changes use consistency checks and
independent adversarial review; they do not invent a runtime red/green sequence.

Each privacy claim names its positive control, falsifier and appropriate evidence layer.
Required coverage cannot disappear through executable-bit changes, workspace omissions or skips.
A local green gate reports what ran; release/integration obligations not executed remain pending.
Workflow defines atomic test-and-implementation work when a separate red test ticket cannot
merge green. Do not disable a regression or weaken a contract to make the scheduler advance.

**Why.** Tests must challenge the intended property rather than encode an implementation's
mistake. Green is meaningful only with known coverage and valid controls.

### VIII. Adversarial Review at Milestones

Every non-trivial ticket receives fresh-context codereview; privacy-critical tickets also
receive independent redteam before commit. Each feature milestone and release additionally
receives cumulative security/privacy and performance/resource review (the `stargate-redteam`
and `stargate-perf` roles). These reviews cannot be replaced by a sum of isolated ticket approvals.
Reviewers MUST be independent of implementation, blind to its rationale and other verdicts
by default, and record their actual tool/model identity and capability limitations. A role name
or two instances of the same tool does not prove expertise or methodological independence.
Reviewers do not delegate. Review findings include severity, affected property, evidence,
uncertainty and a concrete falsification/closure check.

Every verdict binds an exact candidate snapshot, scope, environment and executed/skipped evidence.
Changes invalidate affected evidence and require renewed review before the resulting candidate
is approved. Blocker/Major findings must be fixed or explicitly accepted by the maintainer with
append-only rationale in SECURITY-DECISIONS.md. Acceptance records scope, residual exposure,
owner and a re-evaluation trigger. **Risk acceptance cannot waive this constitution.** A violated
principle requires conforming code or the amendment process; neither an agent nor a ticket may
self-authorize an exception. Unresolved mandatory evidence blocks completion/release.

Before v1.0.0 and each subsequent major release, an external human reviewer with anonymity-systems
experience reviews the release candidate and its security-relevant changes. Findings and closure
are tied to that candidate; material later changes require follow-up review. A release adding or
materially changing a trust boundary, cryptographic identity/authentication mechanism, protected
route or deployment exposure also requires external human review regardless of version number.
Pure implementation repairs within an already reviewed boundary require the ordinary review
loop unless their security impact meets that trigger. A documented impact assessment is required.

**Why.** Independent reasoning, reproducible evidence and human expertise supply different
checks; labels and approval ceremony alone do not establish assurance.

## Tech Stack, Deployment Model, and Non-Goals

### Tech Stack (v1)

The primary planes remain Go and Java/Quarkus with authenticated versioned gRPC over UDS.
The desktop Firefox-family extension targets Mullvad Browser first and LibreWolf second.
Chromium/Safari and mobile are outside v1 scope. The architecture/build contracts specify the
pinned Go/JDK/Quarkus toolchains, SQLite state, packaging and current UI mechanism. Changes
follow IV, VII and VIII; no dependency, version or scope is changed by relocating these details.

### Deployment Model

The Local/LAN/VPS profiles are Docker Compose deployments. The following rules apply to the
actual DP route and CP admin/health listeners in their own network namespaces **and** to every
host publication or forwarding ingress exposing them:

- Local: proxy service listeners and host publications bind loopback only (`127.0.0.1`, and
  `::1` only when explicitly supported/tested). No wildcard or bridge-interface proxy listener
  is authorized by being inside a container. A shared namespace is a design candidate, not an
  automatic solution: it must also satisfy the capability/egress matrix.
- LAN/VPS: proxy listeners bind only addresses of the actual authenticated access tunnel in
  the listener's namespace. A tunnel sidecar elsewhere in the stack is insufficient. Host
  public ingress is limited to the tunnel's authenticated transport endpoint, not the proxy.
- Tunnel loss, address changes and startup/restart races MUST leave no unprotected proxy ingress
  or fallback binding. Deny new access while the required boundary cannot be established.
- Sidecar-internal listeners are separately scoped endpoints, never host-published by default.
  Their addresses/ports and reachable callers MUST enforce III's matrix. Merely sharing a
  bridge or possessing a full-control cookie is not a permitted observation boundary.
- Validate effective addresses and reachability in each supported IP family. Unsupported
  families/configurations must be refused or disabled, not silently exposed.

The proxy MUST refuse startup when these conditions are not met. Environment flags, container
names, tunnel presence checks alone and NAT behavior cannot bypass refusal. The deployment
contract specifies enforcement/probes for ingress **and** egress with positive capture controls.
T125's wildcard permission is superseded; a production repair and fresh-stack evidence are
required before the local profile can be claimed compliant.

### v1.0.0 Scope

Tor (onion and optional clearnet exit), I2P, Nym and explicit Direct are v1 routes. Tor bridges
are a separate reviewed feature, default off. Device bearer enrollment, authenticated local
administration, constrained lifecycle control and token revocation remain in scope. The admin
contract retains WebAuthn with ed25519 SSH-key fallback. Minimal UI, local notifications, external
browser-profile verification and in-extension runtime checks have truthful documented limits.
IPFS/Kubo, mobile, remote notifications and additional routes need later feature specs.

### Non-Goals

Stargate does not protect whole-system traffic, malicious content, an OS-compromised device,
malicious foreign extensions, identifying user behavior, or every timing/fingerprinting channel.
It does not generate endpoint cover traffic or enable Tor bridges by default. It offers no
uptime/SLA guarantee. These exclusions do not waive fail-closed behavior, stated isolation or
CP-outage survival under their explicit preconditions. Underlying route traffic/metadata and
sidecar state have their own named threat-model limitations.

## Development Workflow and Review Discipline

All non-trivial work has a spec/contract, a plan with a Constitution Check and executable tickets.
The canonical lifecycle is docs/process/workflow.md and .specify/memory/review-loop.md. Spec-kit
produces specs/plans/tasks; ticket frontmatter owns lifecycle, dependencies and acceptance.
A Constitution Check reports each property as compliant by evidence, pending evidence, or
conflicting. “PASS (deferred)” and silently accepted implementation drift are not compliance.

Sidecar/routing changes run the relevant contract suites. Inter-plane changes cover both roles,
backwards compatibility for additive minor changes and migration for breaking major changes.
Pre-public compatibility changes require an explicit transition record and synchronized peers;
constitution-version policy does not automatically waive wire-version compatibility.

The single green gate is scripts/verify.sh on the exact review candidate. Check its coverage
report against ticket obligations. Required live/release evidence remains blocking when absent.
Release tags, notes and delivered artifacts identify the reviewed source and finding dispositions.
THREAT-MODEL.md, architecture, BUILD-DIFFS.md and SECURITY-DECISIONS.md accompany relevant changes.
Completed implementation tickets retain their history; newly discovered defects get focused
remediation tickets. Investigation completion must create and connect its implementation work
before dependent feature or closure tickets can advance.

## Governance

This file supersedes all project documents. First seek a conforming design; an existing hack,
failed test, convenient implementation or model recommendation is not by itself amendment grounds.

**Active pre-release procedure:** until first public release, the maintainer may authorize an
amendment in a recorded working session. A dedicated ticket records the requested policy,
alternatives, protection delta, affected documents and exact reviewed candidate. Codereview and
independent redteam are required for any security/privacy/governance-impacting amendment, wherever
located in this document. No agent may accept a weakened guarantee on the maintainer's behalf.
The maintainer's explicit request authorizes work within its stated scope; any additional
weakening or unresolved policy choice must return for a concrete maintainer decision. Public PR
and seven-day comment requirements are deferred until first public release, not until a remote
exists. Historical approvals remain historical; this paragraph governs new amendments.

**After first public release:** amendments are proposed publicly in a PR with at least seven
days for comment, the same impact analysis and independent reviews, and maintainer approval.
The sync impact report and downstream contracts/templates are updated in the same amendment.
Every amendment states whether it clarifies, strengthens or changes permission. Splitting an
amendment across lower-level documents must not bypass this procedure.

Constitution versioning begins at public release: MAJOR for removal/redefinition of a principle
or incompatible governance, MINOR for additions/material expansion, PATCH only for changes with
no semantic effect. Project release versions and wire-protocol versions are separate. Before
release, version 1.0.0 is retained with dated amendment records; the active text and reviewed
snapshot, not a version bump, establish which obligations apply.

A change is not approved merely because it has been written or a gate is green. Unresolved
review findings follow the bounded review loop and escalation menu. External human review
obligations in VIII cannot be waived through a routine finding acceptance.
