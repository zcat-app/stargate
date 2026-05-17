# Specification Quality Checklist: Tor Route — v1 Vertical Slice

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-05-17
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
  - *Note*: Stargate is a protocol-level feature where the protocol identifiers
    (SOCKS5, CONNECT, `.onion`, Tor) and the port number (8881) are part of the
    feature's behavioural surface — not implementation details. The architecture
    spec pins these for the project. The spec references them but does not
    discuss Go libraries, gRPC implementation choices, Quarkus packages, or
    extension framework internals.
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
  - *Caveat*: privacy-tool stakeholders are technical by domain; the spec is
    written for that audience (browser users with anonymity-network familiarity),
    not the general public. Constitution Principle V's "honest threat model"
    framing applies — readers are expected to understand `.onion`, SOCKS5,
    and what "stream isolation" means.
- [x] All mandatory sections completed (User Scenarios, Requirements, Success
  Criteria, Assumptions)

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
  - *Note*: The spec defers two unresolved architecture-level questions to their
    existing `NEEDS CLARIFICATION` markers in `specs/000-architecture/spec.md`
    (Tor sidecar image choice; Mullvad Browser MV2 support window). These are
    flagged in the Assumptions section as carried-forward open questions, not
    duplicated as new spec-level markers.
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable (each SC-00x states a metric, threshold,
  and measurement method)
- [x] Success criteria are technology-agnostic
  - *Caveat*: SC-002 names "Tor circuit IDs" and SC-003 names "DNS queries" —
    these are user-visible privacy concepts in this feature's domain, not
    implementation choices. They are how the privacy property is measured.
- [x] All acceptance scenarios are defined (each user story has 1–3 G/W/T scenarios)
- [x] Edge cases are identified (seven edge cases listed, each linked to an FR
  or a privacy property)
- [x] Scope is clearly bounded (explicit "Out of Scope" section)
- [x] Dependencies and assumptions identified (Assumptions section enumerates
  eight carried decisions)

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria (19 FRs, each
  testable against the privacy-critical tests-first suite)
- [x] User scenarios cover primary flows (P1 happy path, P2 privacy property,
  P3 failure-mode privacy)
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification
  - The spec names *contracts* (SOCKS5h, `IsolateSOCKSAuth`, the architecture
    spec's error template) rather than implementations. The contracts are the
    protocol surface; how Stargate's code satisfies them is `/speckit-plan`
    territory.

## Constitution Alignment

(Added beyond the standard template — Stargate spec quality requires this gate.)

- [x] No requirement contradicts a constitution principle
- [x] Each privacy-critical requirement is explicitly tagged as test-first
  (Principle VII)
- [x] The Constitution Sanity Check table in the spec maps each of the 8
  principles to the FR(s) that satisfy it (or records non-applicability)
- [x] `THREAT-MODEL.md` is referenced for the Tor route (§4.2) and the local
  profile (§3.1); no new threat claims are introduced that lack a
  corresponding `THREAT-MODEL.md` entry

## Notes

- All items pass on first review. The spec is ready for `/speckit-clarify` (if
  further nailing-down is wanted) or `/speckit-plan` directly.
- Two architecture-spec `NEEDS CLARIFICATION` items (Tor sidecar image choice;
  Mullvad Browser MV2 support window) remain upstream of this feature. They
  must be resolved before `/speckit-plan` produces an implementable plan for
  FR-015 (digest pinning) and FR-001/FR-002/FR-003 (extension proxy API
  surface), respectively. Flagged here so the reader does not lose them.
- `AUTH_REQUIRED` is introduced by this feature as a new error code beyond the
  five enumerated in architecture spec §10.1. The architecture spec must be
  amended to add it before the corresponding contract test (FR-016) can land.
  This is a small follow-up edit, not a redesign.
