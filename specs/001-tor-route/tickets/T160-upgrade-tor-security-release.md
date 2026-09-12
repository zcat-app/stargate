---
id: "T160"
title: "Prepare Tor security upgrade with enforced package content pins"
status: "in-review"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "https://forum.torproject.org/t/security-release-0-4-9-12/22096"
phase: "Urgent security update"
story: "-"
blocked_by: ["T099", "T156"]
parallel: false
files_budget: 28
privacy_critical: true
complexity: "medium"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md", "specs/001-tor-route/contracts/torrc.md"]
decision_refs: ["SECURITY-DECISIONS.md"]
remediates: "T099"
decomposed_from: "T140"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T160: Prepare Tor security upgrade with enforced package content pins

## Context

The maintainer explicitly requests upgrading C Tor after the 2026-09-08 security
release 0.4.9.12. The current sidecar pins 0.4.9.11. Upstream identifies memory safety,
client availability and Conflux stream-isolation fixes. Expedite this update ahead
of T139; the new constitution, tests-first and independent review requirements still apply.
Fold T140's pending exact-package-integrity repair into the upgrade so a version bump
does not perpetuate the recorded same-version byte-substitution gap.

## Analysis

- Must hold: official upstream package provenance AND a checked immutable content identity
  before installation; existing Debian snapshot/key/least-privilege/torrc boundaries persist.
- Gated today: structural pins, key fingerprint, snapshot agreement and many protocol contracts.
  The package SHA256 is currently only prose; an authenticated mutable index can change its bytes.
- Residue: native amd64 runtime/build checks do not establish arm64 execution. A version string
  is not a security fix proof; upstream provenance supplies the released fixes, while Stargate
  verifies artifact selection and integration. Historical T058 conclusions need revalidation.
- While T139 is pending, manually inventory intended sources, ensure required gate executables
  and workspace modules are present, stage every new source, and bind both reviews to exact hashes.

## Acceptance

1. Authenticate current official Bookworm metadata using the existing pinned primary key;
   verify Release signature/validity, Packages index hashes and the actual amd64/arm64 .deb hashes.
   Pin Tor 0.4.9.12-1~d12.bookworm+1 and document source URLs, resolved content identities and date.
2. Write and demonstrate failing spec-derived upgrade/content checks before implementation.
   Exercise the actual build installer with deterministic fixtures: correct bytes succeed;
   same-name/version substituted bytes fail before installation; failed download, absent pin
   and unsupported architecture fail closed. The Dockerfile must invoke the checked installer,
   not bypass it with a second unverified Tor installation.
3. Consume the authenticated package through its exact checked local file, retain upstream apt
   signature checking and the existing Debian snapshot/base/key pins, and keep build helpers
   out of the final runtime filesystem. Support amd64 and arm64 pins; refuse other architectures.
   Exclude the mutable Tor repository from non-Tor dependency selection. Preserve a failing
   regression through the actual installer/APT boundary with valid pinned Tor and adversarial
   higher-/same-version dependency metadata; the repaired path must select the Debian snapshot
   or refuse before installation. This is the scoped round-1 redteam RT1 repair, not a dependency
   refresh. Reconcile the stale hash-enforcement residue in THREAT-MODEL §8.6 (RT2).
4. Build the native sidecar, verify the installed package and reported Tor version, and run the
   cold-build package-manifest comparison. Re-run applicable Tor config/control/isolation probes
   against the new image, retaining actual results and any unavailable live evidence explicitly.
   Do not relax isolation or topology guarantees to make an old probe pass; unresolved required
   behavior blocks deployment/release promotion through T161. This ticket delivers the candidate
   source/build preparation; it must not claim the live upgrade validation is complete.
5. Append a supply-chain decision without rewriting committed entries, update the threat model,
   fold T140 into this owner, and revise closure dependencies and preferred order. Keep T155 and
   final security/performance reviews, and add T161 as a promotion/closure blocker. This candidate
   preparation does not close other foundation findings.
   Assign the encountered loss of failing Go test diagnostics to T139; do not expand this
   upgrade into an unrelated protocol-test repair.
6. Run targeted checks and scripts/verify.sh, then fresh independent codereview and redteam on
   the exact staged candidate. Preserve red/green and review evidence with candid limits; deliver
   a focused local commit. No production-stack restart, publication, push or constitution amendment.

## Out-of-scope

Broad dependency/toolchain refreshes, changes to runtime routing/auth/topology, and fixing
unrelated protocol tests. The existing Tor build-input structural test may be updated where
its old name=version assumption must recognize an explicitly verified local package file;
its provenance, snapshot and failure protections must remain covered.

## Notes

The regression is authored within this ticket; empty tests_first is not an exemption.
The current user instruction authorizes expedited priority and deliberate upstream promotion.
Actual deployment promotion remains separate from preparing and reviewing the upgraded image.
