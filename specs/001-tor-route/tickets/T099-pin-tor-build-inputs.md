---
id: T099
title: 'Pin immutable Tor build inputs'
status: in-progress
created: 2026-07-11
last_updated: 2026-07-15
source: review/sol-review.md#M7
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T089, T087]
parallel: false
files_budget: 10
privacy_critical: true
constitution_refs:
  - "IV: Pinned, tested, manually promoted updates"
  - "VI: Open and auditable"
  - "VII: Sidecar contract test-first"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md §FR-015
  - specs/000-architecture/spec.md §7
  - specs/000-architecture/spec.md §12.4
decision_refs:
  - SECURITY-DECISIONS.md §"2026-07-04 — Tor sidecar trust rationale (FR-015)"
remediates: T014
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T099: Pin immutable Tor build inputs

## Context

The Tor Dockerfile verifies a signing key but installs unversioned packages
from mutable apt repositories. Rebuilding the same commit can therefore select
different Tor or Debian bytes.

## Analysis

Property map (grounding-verified 2026-07-15; `privacy_critical: true` →
required per `docs/process/analysis.md`). Constitution principles land here
as concrete properties, not 23 KB of prose.

- **Must hold**
  - Base image is digest-pinned in BOTH stages (already true today:
    `debian:12-slim@sha256:60eac759739651111db372c07be67863818726f7548048707c90979bda511df`)
    — T099 does not regress this (Principle IV).
  - Every `apt-get install` resolves from an immutable snapshot
    (`snapshot.debian.org` for the Debian closure; the Tor repo is already
    `deb.torproject.org` `signed-by=`-bound) with explicit versions — no
    unversioned `apt-get install <pkg>` remains in either stage (Principle IV).
    This is the load-bearing change: SECURITY-DECISIONS.md lines 592–612
    document that `libssl3`/`libevent-2.1`/`zlib1g`/`libc6` (Tor's link-time
    closure) currently float fresh from Debian's archive at every build;
    snapshot pinning freezes them.
  - apt's `Valid-Until` / `Date` metadata checks stay ENABLED — the snapshot's
    `InRelease` expiry must fail the build closed, never
    `Acquire::Check-Valid-Until "false"` (Principle IV; acceptance #2).
  - The Tor Project signing-key fingerprint verification + `PUB_COUNT==1`
    TOFU-resistance assertion are preserved unchanged (acceptance #2; the
    keyring stage is not weakened by the snapshot switch).
  - Upgrades remain a manual, review-driven promotion (Principle IV step 1–4).

- **Gated**
  - A cold-cache rebuild confirms the resolved package set (name + version +
    hash) is stable across rebuilds (Principle VII — test-first for the
    sidecar contract; acceptance #3).
  - The live Tor sidecar contract (`tests/contract/torrc/live_sidecar_test.go`,
    T032/T087) passes against the snapshot-pinned image (Principle VII).
  - `scripts/verify.sh` stays green (acceptance #6).

- **Residue** (carried to the threat model + SECURITY-DECISIONS per
  acceptance #4; Principle V — honest threat model)
  - `snapshot.debian.org` and the Tor repo operator remain in the Tor TCB.
    Snapshot pinning freezes WHICH bytes, it does not vouch for their
    trustworthiness — that still rides Debian's / the Tor Project's archive
    signing (SECURITY-DECISIONS.md §"Residual risk").
  - The final composed image digest is still RELEASE-TAG-TIME (T081); T099
    pins build INPUTS, not the final image. T081 `blocked_by: [..., T099]`
    already encodes this ordering.

- **Flagged at grounding (resolved into acceptance 2026-07-15):**
  - **`final image digest stable` (was acceptance #3) over-specified.** Apt
    postinst scripts, dpkg status mtimes, and Docker layer/config `created`
    timestamps mean a byte-identical image digest is NOT automatic from
    snapshot pinning alone — it would additionally need `SOURCE_DATE_EPOCH` +
    reproducible-layer discipline. **Resolved:** #3 downscoped to a gated
    *stable package manifest*; byte-stable digest is a stretch goal, variance
    recorded in `BUILD-DIFFS.md` if unreachable (Principle VI precedent).
  - **Constitution Principle VI drift — IN scope.** Principle VI lists
    reproducibility tiers for the Go data plane, Quarkus JVM/native, and the
    extension but NOT the Tor sidecar image. **Resolved:** acceptance #4 adds
    a Tor-sidecar tier (best-effort, snapshot-pinned) via a pre-release
    amendment NOTE (no version bump), following the T091 pattern. VI is
    outside the I/III/V privacy core so mandatory redteam does not trigger;
    running it voluntarily remains good practice.

## Acceptance

1. Resolve Debian and Tor packages from immutable snapshot locations with
   explicit versions and retained cryptographic hashes; no unversioned
   `apt-get install` remains.
2. Preserve fingerprint verification and fail closed on missing, expired, or
   hash-mismatched repository metadata.
3. Add a reproducibility/grounding test that rebuilds from a cold cache and
   confirms the **resolved package set (name + version + hash) is stable**
   across rebuilds. A byte-stable final image digest is a **stretch goal**,
   not a gate: apt postinst scripts, dpkg status mtimes, and Docker layer
   `created` timestamps make byte-identity non-automatic from snapshot
   pinning alone (it would need `SOURCE_DATE_EPOCH` + reproducible-layer
   discipline). If the digest is not byte-stable within budget, record the
   variance in `BUILD-DIFFS.md` (Principle VI precedent) and keep the
   package-manifest check as the gated property.
4. Amend Constitution **Principle VI** to add a Tor-sidecar reproducibility
   tier (best-effort: snapshot-pinned build inputs; package-manifest stable;
   byte-stable digest where achievable, variance in `BUILD-DIFFS.md`). Record
   the amendment as a pre-release NOTE in the constitution header (no version
   bump — project is pre-release) following the T091 amendment pattern, with
   a Sync-Impact-Report entry and templates-reviewed block.
5. Update FR-015, architecture, threat model, build documentation, and
   `SECURITY-DECISIONS.md` with the exact trust and rotation procedure.
6. Refine T081 to use a two-phase candidate flow: build/record/review digests,
   then tag the exact commit containing its release metadata. No post-tag
   source commit or decision-log mutation is permitted.
7. Tor contract tests and `scripts/verify.sh` pass.

## Out-of-scope

Background package updates or mutable-tag promotion.
