<!--
Pre-release amendment log (constitution version: 1.0.0 — UNCHANGED)
====================================================================

The project has shipped no binary and has no public remote. The earlier
"v1.1.0" entry below (a version bump for the JDK 25 / Quarkus 3.33 pin) was
inappropriate: bumping a constitution version for a design decision on an
unreleased project is meaningless signalling with no consumers to signal to.
It is retained below as a historical record but its version bump is
SUPERSEDED — the constitution stays at 1.0.0.

Both pre-release design changes are recorded here as amendment NOTES, not
version bumps:

  1. (was "v1.1.0") Control-plane platform pinned to JDK 25 LTS / Quarkus
     3.33 LTS / Mandrel 25. Tech Stack bullet updated. No principle touched.
  2. (T091) Principle III bullet 3 rewritten — the browser-hardening
     guarantee moves from a false extension-API enforcement claim (sol-review
     B4: Firefox's stable WebExtensions does not expose `network.trr.mode`,
     `network.dns.over_tls.*`, `network.http.http3.enable`) to an externally
     verified precondition (release-cadence, against a test profile that
     models the target browser's hardened defaults) plus a narrow runtime
     gate (WebRTC via `privacy.network.peerConnectionEnabled`; SOCKS5h via
     `proxy.ProxyInfo`). Per the stargate-redteam pass (2026-07-12), the
     wording is explicit that runtime fail-closed covers WebRTC only;
     DoH/DoT/HTTP-3 are release-cadence-verified, not runtime-enforced, and
     their post-verification drift is accepted residue named in THREAT-MODEL
     §5.4/§5.5. Downstream sections amended: arch §14.2/§14.5; spec FR-004 +
     Constitution Sanity Check row III; plan Constitution Check row III;
     THREAT-MODEL §2.7/§5.3/§5.4/§5.5. Dependent tickets T034b/T051/T054/
     T055 refined at step 17 (acceptance #6), only after acceptance.

  3. (T099) Principle VI reproducibility tiers — a new tier added for the
     Tor sidecar image (and Stargate-built sidecars): best-effort
     reproducible via snapshot.debian.org-pinned build inputs +
     =version pins; the gated property is a byte-stable package manifest
     (asserted at release cadence); the final image digest is NOT
     guaranteed byte-stable and its expected variance is documented in
     BUILD-DIFFS.md. This closes a drift flagged at T099 grounding: the
     tiers previously enumerated only the Go data plane, Quarkus
     JVM/native, and the extension. Downstream sections amended: arch
     §7 Tor row + §12.4; spec FR-015; THREAT-MODEL §2.6/§5.9;
     SECURITY-DECISIONS.md (Debian archive snapshot pin entry).
     Principle VI is outside the I/III/V privacy core, so the mandatory
     stargate-redteam gate does not trigger; running it voluntarily
     remains good practice.

     Templates reviewed against this amendment:
       ✅ .specify/templates/plan-template.md      — no edit required.
       ✅ .specify/templates/spec-template.md      — no edit required.
       ✅ .specify/templates/tasks-template.md     — no edit required.

Constitution semver-on-amendments + the 7-day public comment window become
BINDING at first public release. Until then, amendments are recorded here
without version bumps. T091 nonetheless runs `stargate-redteam` (good
practice for a Principle III change) and the maintainer opens a comment
window via the governance PR.

**T091 pre-release approval (2026-07-12).** The maintainer approves the
Principle III bullet 3 amendment pre-release. The 7-day public comment
window and the governance-PR step are **deferred to first public release**
per the v1.1.0 framing above (no public remote with consumers, no team, no
binary shipped). The `stargate-redteam` gate ran (4 rounds; Major M1
resolved + closed at `redteam/findings/closed/20260712-001-...md`; minors
m1–m5 fixed; CLEAN on round 4) and the boundary is endorsed as
constitutionally sufficient for v1 given the named residue. The maintainer
records this approval here in lieu of the PR/comment-window ceremony that
becomes binding only at first public release.


Sync Impact Report — Constitution v1.1.0  (SUPERSEDED — see note above)
========================================================================

Version change: 1.0.0 → 1.1.0  [THIS BUMP IS REVERTED — pre-release design
decision, no consumers to signal to. Retained for history only.]
Reason: Pin control-plane platform from JDK 21+ (open-ended) to JDK 25 LTS
and Quarkus 3.33 LTS, with matching Mandrel 25 native-image builder.

Principles modified: none.
Sections modified:
  - Tech Stack, Deployment Model, and Non-Goals → Tech Stack (v1) bullet
    for control plane (concrete platform versions pinned).

Templates reviewed against this amendment:
  ✅ .specify/templates/plan-template.md      — no edit required.
  ✅ .specify/templates/spec-template.md      — no edit required.
  ✅ .specify/templates/tasks-template.md     — no edit required.

Follow-up artefacts updated in this PR:
  ✅ specs/000-architecture/spec.md §12.2  — JDK / Quarkus / Mandrel pins.
  ✅ specs/000-architecture/spec.md §15    — added open question 9
                                            (Quarkus/JDK compat matrix).
  ✅ CONTRIBUTING.md prerequisites         — JDK / Quarkus / Mandrel pins.

Deferred:
  - Concrete Mandrel 25 builder image digest pinned at first release tag
    once Quarkus 3.33 LTS / JDK 25 runtime compatibility is verified
    against the Quarkus platform matrix (tracked in arch spec §15 #9).

Governance note:
  This amendment was applied during the pre-GitHub scaffolding phase, before
  the repo had a public remote. The formal governance flow defined in this
  constitution (PR + 7-day public comment window + stargate-redteam pass
  for privacy-critical principles) was not executable at the time:
    - No public remote existed, so no PR or comment window was possible.
    - The stargate-redteam subagent definition is still a TODO.
  This is recorded here so future readers (and any later redteam pass over
  repo history) see plainly that v1.1.0 was a maintainer-only change made
  before the governance mechanism was operational — not a skipped step.
  Principles I, III, V are unchanged by this amendment, so the redteam
  requirement would not have applied even once available.
  The full governance flow becomes binding the day the repo gets a public
  remote; subsequent amendments follow it without exception.


Sync Impact Report — Constitution v1.0.0 (initial ratification)
================================================================

Version change: (none) → 1.0.0
Reason: Initial constitution for the Stargate project.

Principles (all newly added):
  I.   Dumb Router (NON-NEGOTIABLE)
  II.  Plane Separation
  III. Privacy-Preserving by Construction
  IV.  Pinned, Tested, Manually Promoted Updates
  V.   Honest Threat Model
  VI.  Open and Auditable
  VII. Tests-First for Privacy-Critical and Contract Code
  VIII.Adversarial Review at Milestones

Sections added:
  - Tech Stack, Deployment Model, and Non-Goals
  - Development Workflow and Review Discipline
  - Governance

Templates reviewed against this constitution:
  ✅ .specify/templates/plan-template.md      — Constitution Check is a derive-at-planning-time placeholder; no edit required.
  ✅ .specify/templates/spec-template.md      — User-story format does not contradict any principle; no edit required.
  ✅ .specify/templates/tasks-template.md     — Updated: "Tests are OPTIONAL" replaced with explicit reference to Principle VII; per-story test headings updated.
  ✅ .specify/templates/commands/                — Directory not present in this project; skipped.

Follow-up artefacts referenced by this constitution but authored separately:
  TODO(ARCHITECTURE.md):       concrete system design — modules, ports, schemas
  TODO(THREAT-MODEL.md):       per-mode and per-route threat models referenced by Principle V
  TODO(SECURITY-DECISIONS.md): append-only log of accepted findings (Principle VIII)
  TODO(CONTRIBUTING.md):       contributor onboarding, AI-assisted workflow guidance
  TODO(BUILD-DIFFS.md):        documented expected variations in native-image reproducibility
  TODO(.claude/agents/):       definitions for stargate-redteam and stargate-perf subagents
  TODO(specs/000-architecture/): system architecture spec derived from this constitution
-->

# Stargate Constitution

Stargate is an open-source, multi-protocol privacy-routing proxy that lets a user
direct browser traffic to Tor, I2P, a Nym mixnet, or the clear internet from a
single configured browser, while preserving the privacy properties each underlying
network is designed to provide. This constitution defines the non-negotiable
principles that govern how Stargate is designed, built, reviewed, and evolved.

## Core Principles

### I. Dumb Router (NON-NEGOTIABLE)

The data plane is a transport switchboard. It MUST NOT:

- parse request or response payloads beyond what transport requires
  (e.g., HTTP `CONNECT host:port` parsing, SOCKS5 framing);
- terminate TLS or interpose CA certificates for any traffic class;
- resolve hostnames locally (SOCKS5h is mandatory for all routed traffic);
- modify, inspect, or log request or response headers;
- generate cover, decoy, or chaff traffic from the user's endpoint;
- persist request metadata to disk.

Each listening port forwards to exactly one upstream protocol; the upstream
binding is fixed at startup, not chosen per request. Routing decisions are made
by the client (the browser extension), not by the proxy.

**Why.** The proxy is the privacy TCB's transport layer. Any function beyond
byte forwarding expands the attack surface, creates new categories of leak, and
concentrates trust that should remain at the client edge. Endpoint-generated
cover traffic is rejected because it provides negligible protection against
realistic adversaries while creating identifiable patterns and a false sense
of security; timing-correlation resistance is the responsibility of the
underlying mixnet, not the user's endpoint.

### II. Plane Separation

Stargate is two services with distinct lifecycles, languages, and concerns:

1. **Data plane** — Go binary. Network transport, sidecar coordination,
   per-port routing. Owns the privacy-critical hot path.
2. **Control plane** — Quarkus (Java) application. Configuration management,
   admin UI, sidecar lifecycle commands, audit logging.

The data plane MUST continue routing if the control plane is unreachable. The
control plane is an advisor, never a hot-path participant; it MUST NOT sit in
the request path.

All cross-plane communication uses a **versioned, authenticated contract**
(gRPC over a Unix-domain socket, mutually authenticated by keys generated at
install time). Schema changes follow semantic versioning: additive changes
in minor versions; breaking changes require a major version bump with a
documented migration.

**Why.** Independent failure modes mean a bug or crash in the management layer
cannot disrupt routing, and a compromise of the management UI cannot silently
corrupt routing decisions. Versioned contracts make breaking changes deliberate
and reviewable.

### III. Privacy-Preserving by Construction

Privacy properties hold by mechanism, not by policy. Specifically:

- **Per-user state is client-side only.** Routing preferences, per-domain
  memory, and route history live in the browser extension's local storage.
  The proxy MUST NOT persist any per-user routing data.
- **All routed requests use SOCKS5h** to upstream sidecars; the proxy MUST
  NEVER resolve a destination hostname locally.
- **Non-Direct routes require a hardened target-browser configuration that
  is verified as a release-cadence precondition, not enforced via the
  WebExtension API.** The browser profile (Mullvad Browser by default) must
  have DNS-over-HTTPS off, DNS-over-TLS off, WebRTC fully disabled, and
  HTTP/3 / QUIC off, verified out-of-band against a test profile that models
  the target browser's hardened defaults before a release ships. The
  extension gates only the surfaces Firefox's stable WebExtensions API
  truthfully exposes at runtime — WebRTC via
  `privacy.network.peerConnectionEnabled`, and per-request SOCKS5h via
  `proxy.ProxyInfo` (`proxyDNS: true` + SOCKS5 username/password). It does
  NOT claim to read or write the DoH/DoT/HTTP-3 preferences, which stable
  Firefox WebExtensions do not expose. **Non-Direct routing is fail-closed
  at runtime against WebRTC** (the one surface the extension can read); the
  DoH/DoT/HTTP-3 surfaces are release-cadence-verified, not
  runtime-enforced, and their post-verification drift is accepted residue
  named in THREAT-MODEL §5.4/§5.5. (The concrete verification mechanism, the
  failure UX, and the foreign-extension inventory decision live in the
  architecture spec and THREAT-MODEL; this constitution states only the
  invariant. Amended by T091 — see Sync Impact Report.)
- **Tor routes use per-first-party-domain SOCKS5 stream isolation.** The
  extension passes the first-party domain as the SOCKS5 username, forcing
  distinct Tor circuits per origin and preventing cross-site correlation
  through a shared circuit.
- **Logs contain only aggregate counters at ≥1 hour resolution.** The proxy
  MUST NOT log destination hostnames, full URLs, header values, per-request
  timestamps, or any other per-request metadata.
- **Stargate makes no outbound network connections except those a request
  explicitly routes through.** Status, monitoring, and notification channels
  are local-only in v1; opt-in outbound channels are separate features with
  their own documented threat models.

**Why.** Privacy claims that depend on configuration discipline drift over
time. Privacy claims enforced by code remain true under future changes,
contributor turnover, and operator mistakes.

### IV. Pinned, Tested, Manually Promoted Updates

All external components are referenced by **image digest** (sha256), never by
mutable tag. This applies to sidecar images (Tor, i2pd, Nym client; Kubo
deferred to v2), base images used in Stargate's builds, and Stargate's own
release artefacts.

Updates land in the repository through this flow:

1. An automated dependency tracker (e.g. Renovate) opens a PR proposing a new
   digest.
2. CI runs **sidecar contract tests** verifying the narrow interfaces Stargate
   depends on (e.g., "Tor SOCKS5 still responds on the expected port and
   successfully connects to a known onion service").
3. A human reviews the changelog and merges.
4. End users receive updates only by explicit action in the admin dashboard
   ("Update available; review and apply"). Background auto-update is forbidden
   for all components Stargate ships or vendors.

**Why.** A privacy tool's Trusted Computing Base must not change silently.
Update mechanisms are themselves remote-code-execution channels; making them
deliberate and auditable is non-negotiable.

### V. Honest Threat Model

Every deployment mode (Local / LAN / VPS) and every route
(Direct / Mixnet / Tor / I2P / VPN) has a documented threat model in
`THREAT-MODEL.md` stating:

- what the route or mode protects against;
- what it does NOT protect against;
- which third parties are trusted, and what they can observe;
- known leaks (SNI, exit-node visibility, clock-skew failure modes, etc.)
  and their mitigations or accepted residual risk.

No marketing claims. No privacy property is asserted beyond what the
underlying anonymity network's design supports. Non-goals are documented
explicitly (see "Non-Goals" below) to prevent users from drawing protective
conclusions Stargate does not deliver.

**Why.** A privacy tool that overstates its protections is worse than one that
understates them. Users make security decisions based on stated guarantees;
silent gaps cause real harm.

### VI. Open and Auditable

Stargate is open-source under the **Apache 2.0 license**, hosted on GitHub
(a Codeberg mirror is a v1.5+ consideration).

Builds are reproducible at the following tiers:

- **Go data plane**: fully byte-reproducible. Verified in CI on every release
  with `-trimpath`, `-buildvcs=false`, and a pinned Go toolchain.
- **Quarkus JVM bytecode**: fully reproducible via `reproducible-build-maven-plugin`
  and pinned Maven/JDK versions.
- **Quarkus native-image**: best-effort reproducible, built from verified
  bytecode. Expected variations (build IDs, embedded timestamp metadata) are
  documented in `BUILD-DIFFS.md` so auditors verify only the unexpected diffs.
- **Tor sidecar image (and Stargate-built sidecars)**: best-effort
  reproducible. Build inputs are pinned to an immutable `snapshot.debian.org`
  run with explicit `=version` pins, so a clean rebuild selects a
  byte-stable package manifest (the gated property, asserted at release
  cadence). The final image digest is NOT guaranteed byte-stable — apt
  postinst scripts, dpkg status mtimes, and Docker layer `created` timestamps
  introduce expected variance, documented in `BUILD-DIFFS.md`. The signed
  InRelease + per-package sha256 verification (Principle IV) is the integrity
  guarantee; reproducibility makes the resolved set auditable, not the
  maintainer trustworthy. (Added by T099; see `SECURITY-DECISIONS.md`.)
- **Browser extension**: fully reproducible via deterministic zip packaging.

This constitution, the architecture spec, the threat model, and the security
decision log are **version-controlled artefacts**, amended through documented
governance, never through undocumented behaviour change. Critical code carries
doc-style comments linking to the principle, spec, or threat-model entry that
motivates the design.

**Why.** Trust in a privacy tool requires the ability to verify that the
binary you run was built from the source you reviewed. Reproducibility makes
audits transferable: one auditor's verification benefits all users.

### VII. Tests-First for Privacy-Critical and Contract Code

Any code path touching DNS resolution, routing decisions, header handling,
authentication, or sidecar contracts requires a **test that demonstrates the
privacy property before the implementation lands.**

Test discipline by code category:

| Category                                          | Discipline                                      |
|---------------------------------------------------|-------------------------------------------------|
| Privacy-critical paths (DNS, routing, headers, auth) | Test-first (MANDATORY)                          |
| Public API surfaces (REST, gRPC contracts)        | Contract test-first                             |
| Bug fixes                                         | Regression test required                        |
| Networking hot path (Go data plane)               | Integration test-driven (real sockets, sidecars in harness) |
| Other code                                        | Tests required at PR time; order flexible       |
| Infrastructure (Docker, scripts, packaging)       | Smoke tests at minimum                          |

AI-assisted implementation follows a tests-first workflow documented in
`CONTRIBUTING.md`: tests are derived from the spec, then implementation is
driven to satisfy the tests. Tests are not generated post-hoc to fit existing
code.

**Why.** Privacy bugs are silent — they leak without breaking functionality.
Tests are the regression line. For AI-assisted development specifically, tests
act as an executable specification that the agent's output can be verified
against, rather than against vibes.

### VIII. Adversarial Review at Milestones

Each feature spec and each release passes documented adversarial review by
two subagents:

- **`stargate-redteam`** — security and privacy reviewer with anonymity-systems
  context. Verifies code against this constitution and the threat model.
  Specifically checks DNS handling, header propagation, log content, sidecar
  contract assumptions, auth bypass paths, port binding, browser API misuse,
  and inter-plane contract leaks.
- **`stargate-perf`** — performance and resource reviewer. Verifies per-request
  allocations, blocking calls in async contexts, goroutine and connection
  leaks, native-image build correctness, and cold-start time.

Each run produces a findings document tagged **Blocker / Major / Minor / Info**.
Blocker and Major findings are resolved before merge OR explicitly accepted
with rationale recorded in `SECURITY-DECISIONS.md` (append-only). Agents do
not see prior reviews by default — fresh-eyes context is the value.

Before tagging `v1.0.0`, Stargate undergoes **one external human security
review** by a reviewer with anonymity-systems experience. Subsequent major
releases (`v2.0.0`, `v3.0.0`, …) repeat this requirement.

**Why.** Privacy bugs evade automated detection. Adversarial review by
independent agents catches what authors miss. External human review catches
what agents miss. Both are required for credibility.

## Tech Stack, Deployment Model, and Non-Goals

### Tech Stack (v1)

- **Data plane**: Go (pinned toolchain version). Network primitives via the
  standard library and `golang.org/x/net/proxy`. Static binary, `-trimpath`.
- **Control plane**: **Quarkus 3.33 LTS on JDK 25 LTS**, packaged as
  native-image for releases and JVM-mode for development. Hibernate ORM with
  Panache over SQLite (WAL mode). Qute templates for the admin UI; a React
  frontend is a v1.5+ consideration.
- **Inter-plane transport**: gRPC over Unix-domain socket; protobuf v3 with
  explicit semantic versioning.
- **Browser extension**: WebExtensions API, Firefox-ESR RFP-safe subset.
  First-class target: **Mullvad Browser**. Tested-secondary: **LibreWolf**.
  Not supported: Chrome, Edge, Vivaldi, Safari.
- **Sidecars (v1)**: Tor, i2pd, Nym client.
- **Sidecars (deferred to v2)**: Kubo (IPFS). Port 8883 is reserved; the
  architecture must accommodate future inclusion without redesign.
- **Storage**: SQLite for control-plane state; Docker named volumes for
  per-sidecar persistent state.

### Deployment Model

Stargate ships as a **Docker Compose stack**. Three documented profiles, with
corresponding `docker-compose.<profile>.yml` files:

1. **Local** — single-user, single-machine. All bindings on `127.0.0.1`.
   No tunnel sidecar.
2. **LAN** — household, multi-device on one network. WireGuard sidecar;
   the proxy binds only to the WireGuard interface.
3. **VPS** — remote gateway, accessed from devices over WireGuard or Tailscale.
   The proxy binds only to the tunnel interface.

**Privacy invariant**: the proxy MUST refuse to start if it would bind to a
non-loopback interface without a corresponding tunnel interface present in
the same compose stack.

### v1.0.0 Scope

- **Routes**: Tor (`.onion` and optional clearnet-via-Tor-exit), I2P (`.i2p`),
  Nym mixnet (clearnet), Direct (clearnet, no privacy).
- **Tor bridges**: supported, toggleable in the admin UI (default off);
  delivered as a dedicated feature spec.
- **Auth**: per-device bearer tokens enrolled via QR/JSON; admin login via
  WebAuthn with ed25519 SSH-key fallback.
- **UI**: minimal Qute-based dashboard for status, sidecar lifecycle, bridge
  management, and token revocation.
- **Notifications**: local desktop notifications only; outbound notification
  channels (SimpleX, ntfy, etc.) are deferred to v1.5+ as opt-in features.
- **Onboarding aids**: install-time configuration audit by the extension
  (DoH / WebRTC / QUIC / no foreign extensions); small static blocklist for
  Tor2web-style onion gateways and known fake-onion patterns.

### Non-Goals

Stargate explicitly does **not**:

- **Replace a VPN.** Stargate protects only traffic from browsers configured
  to use it; whole-system traffic protection is out of scope.
- **Protect against malicious destinations.** Hostile onion services,
  phishing pages, and in-page tracking are out of scope; Stargate is
  transport, not content.
- **Protect against compromise of the user's device.** Keyloggers, screen
  recorders, malicious browser extensions, evil-maid attacks, and OS-level
  compromise are out of scope.
- **Protect against user behaviour.** Logging into an identified account
  through Stargate identifies the user to that destination; the technology
  cannot fix social patterns.
- **Generate cover or decoy traffic** from the user's endpoint.
  Timing-correlation resistance is the responsibility of the underlying
  mixnet (Nym).
- **Provide mobile support in v1.** Desktop browsers only.
- **Function as a censorship-circumvention tool by default.** Tor bridges
  are supported but disabled by default; users in censored networks enable
  bridges explicitly.
- **Guarantee availability.** Stargate is best-effort software; no uptime
  or service-level guarantees are made.

## Development Workflow and Review Discipline

### Spec-Driven Development

All non-trivial changes flow through spec-kit:

1. `/speckit-specify` produces a feature spec at `specs/NNN-feature/spec.md`.
2. `/speckit-clarify` (optional) surfaces ambiguities before planning.
3. `/speckit-plan` produces an implementation plan referencing this
   constitution. The plan MUST include an explicit **Constitution Check**
   verifying that no principle is violated.
4. `/speckit-tasks` produces an actionable task list.
5. `/speckit-implement` executes the tasks.

Specs that contradict the constitution are revised, not implemented. If a
contradiction is intentional and load-bearing, it is processed through the
amendment flow (see Governance) rather than the feature flow.

### Contract Tests

Each sidecar has a contract test suite at `tests/contract/<sidecar>/`. The
contract codifies the narrow interface Stargate depends on. CI runs contract
tests on every PR that touches sidecar image digests or routing code.
Contract-test failures block merge.

### Inter-Plane Contract

The gRPC schema between data plane and control plane lives at
`proto/stargate/v1/`. Schema changes require:

- a backwards-compatibility test for minor versions;
- a migration test and explicit major version bump for breaking changes;
- review against both data-plane and control-plane code paths.

### AI-Assisted Development

This project is developed in collaboration with AI coding assistants.
Conventions:

- Tests are written **before** implementation when generated with AI
  assistance, derived from the spec.
- AI-generated code carries the same review burden as human-generated code.
  There is no "AI exception" to Principle VIII (Adversarial Review).
- This constitution is the authoritative source for AI agents working on
  the project. Spec-kit commands reference it via Constitution Check gates.

### Build and Release

- Releases are tagged in git as `v<major>.<minor>.<patch>`. Project versions
  evolve independently of constitution versions.
- Reproducible-build verification runs in CI on every tagged release.
- Release notes link to: changed specs, completed feature numbers, security
  review findings, and any `SECURITY-DECISIONS.md` additions made for the
  release.

### Documentation Alongside the Constitution

- `ARCHITECTURE.md` — concrete system design (modules, ports, schemas),
  derived from this constitution and `specs/000-architecture/spec.md`.
- `THREAT-MODEL.md` — per-mode and per-route threat models referenced by
  Principle V.
- `SECURITY-DECISIONS.md` — append-only log of accepted findings (Principle VIII).
- `CONTRIBUTING.md` — contributor onboarding, AI-assisted workflow guidance.
- `BUILD-DIFFS.md` — documented expected variations in native-image
  reproducibility.

## Governance

This constitution supersedes all other documents in the project. Where a
spec, implementation, or comment conflicts with the constitution, the
constitution wins.

**v1 governance is intentionally light-touch.** The project maintainer makes
amendment decisions in the open. Amendment process:

1. Proposed amendment lands as a pull request modifying this file.
2. Minimum public comment period: **7 days** via GitHub issue or PR discussion.
3. Amendments to Principles I, III, or V (the privacy-critical principles)
   additionally require a passing `stargate-redteam` run against the
   proposed change.
4. The maintainer approves merge.
5. The Sync Impact Report at the top of this file is updated with the
   change summary, modified principles, and templates flagged for review.

Versioning follows semantic versioning:

- **MAJOR** — backwards-incompatible governance changes, or removal/redefinition
  of a principle.
- **MINOR** — new principle or section added; material expansion of existing
  guidance.
- **PATCH** — clarifications, wording, typo fixes; no semantic change.

External security review is required before tagging a `v1.0.0` major release
of the project; subsequent major releases (`v2.0.0`, `v3.0.0`, …) repeat
this requirement.

Compliance with the constitution is verified at every `/speckit-plan`
gate. Pull requests that introduce code violating a principle are blocked
until either the code is changed or the constitution is amended through
the process above.

**Version**: 1.0.0 | **Ratified**: 2026-05-17 | **Last Amended**: 2026-05-17 (pre-release design amendments recorded in the log above; no version bump until first public release)
