---
id: T213
title: "Restore fresh Tor builds with reviewed 0.4.9.14 package promotion"
status: in-progress
created: 2026-10-09
last_updated: 2026-10-09
source: "Maintainer-authorized prerequisite: T212 cold T162 failed after genuine Tor index retrieval; pinned 0.4.9.13 removed upstream. Authorization: 2026-10-09, plan v2 and frozen T213 proposal hashes recorded below."
phase: "Foundation dependency availability"
story: "-"
blocked_by: [T211]
parallel: false
files_budget: 12
files_scope:
  - sidecars/tor/Dockerfile
  - sidecars/tor/tor-packages.sha256
  - sidecars/tor/package-closure.lock
  - tests/contract/security-decisions/tor_package_integrity_test.sh
  - THREAT-MODEL.md
  - BUILD-DIFFS.md
  - SECURITY-DECISIONS.md
  - reviews/T213/README.md
  - specs/001-tor-route/tickets/T213-promote-tor-package-for-fresh-builds.md
  - specs/001-tor-route/evidence/T213-tests-first.json
  - specs/001-tor-route/STATUS.md
  - docs/process/reviewer-scorecard.md
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "V: Honest Threat Model"
  - "VI: Open and Auditable"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
  - "VIII: Adversarial Review at Milestones"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - "specs/001-tor-route/spec.md FR-015"
  - "specs/001-tor-route/contracts/torrc.md"
  - "THREAT-MODEL.md"
decision_refs:
  - "SECURITY-DECISIONS.md: removed Tor artifacts fail closed and require manual refresh; T160/T177"
  - "Maintainer authorization 2026-10-09: plan v2 SHA256 5a04c840e8a213274e1cba09085b7337e2608cf21527a3fe3281dbe612761d31; frozen proposal SHA256 774ab8da6e0f479584c27bcf62f3ee79acf1cb72051dc0946198504f3226b0a3"
  - "Independent Astra plan evaluation v2 SHA256 de831c443860f71b9b11f11f48015ae56f0f48feb8fb0de034b1aa260c93a73c: READY, no must-fix; plan review only, not implementation approval"
reviews: {}
overrides: []
aborted_attempts: [{ date: 2026-10-09, round: 2, reason: "run-task --reset", history: target/runs/T213.review-history }]
reopens: [{ date: 2026-10-09, blocker: T214, resolved_by: 81f10aaedb5710b42745bb2485457c4081fb33cd, prior_deferral_commit: 83e247b0e5b35bcd9b85e638eeb567f955e3cef3, prior_deferral_reason: blocked-on-new-ticket }]
redteam_findings: []
clarity_check: {}
---

# T213: Restore fresh Tor builds with reviewed 0.4.9.14 package promotion

## Context

T212's actual cold Docker-tier T162 build fetched genuine Tor InRelease and amd64
Packages metadata, then failed because the selected0.4.9.13 package is no longer
listed. Independent current signature/hash verification confirms0.4.9.14 is listed;
the old pool URL returns404. T177 documented the same failure for0.4.9.12.
This separate prerequisite follows the existing deliberate manual-refresh policy.
It does not fold production dependency changes into T212's exact10path scope.

Both candidate architectures have already been retrieved and checked against
current signed official metadata, solely as preparation. They have not been
installed, executed, promoted or qualified. Input proof is retained under
`.scratch/tmp/T212/root-tor-catalog-t_4zhob6/`; candidate audit SHA256
705833b3977198f367262de1973ccc052b6d54e929ca67db0e50c5d1700c5974.
The independent Astra advisory SHA256 is
d6e8c65157c9f3dc143d93cb2ba8fa22e80a58ff140b99f4a67528867e97b923.

Must hold: only the selected Tor artifact/version changes. Preserve current key
verification/revocation behavior, Debian snapshot/index/base pins, dependency-source
isolation, checked local-file/no-download installation, exact torrc, non-root
runtime, diagnostics policy and all negative controls. Package identity is not
runtime qualification. Availability remains time-limited: this ticket does not
invent an archive policy or guarantee indefinite upstream retention.

Constitution Check: IV requires explicit reviewed promotion and independently
authenticated content; V/VI record exact inputs/results and their limits; VII/VIII
require meaningful tests-first plus native GLM/Astra implementation approval.

## Acceptance

1. Ground the complete source, authority and T212 deferral checkpoint before edits.
   Before changing Dockerfile/pins/closure, update the existing package-integrity
   contract to expect0.4.9.14-1~d12.bookworm+1. Capture its meaningful failure against
   the actual START via `scripts/test-first-evidence.py red T213 -- bash
   tests/contract/security-decisions/tor_package_integrity_test.sh`; after the fix,
   record identical-command GREEN. Preserve both architectures, same-version
   substitution, missing pin, failed download, unsupported architecture and hostile
   dependency-metadata controls. Do not call this a security release without a
   verified upstream advisory.
2. Independently verify official Bookworm InRelease signature/validity against the
   unchanged primary fingerprint; bind both Packages indexes to that signed
   metadata, and actual amd64/arm64 artifacts to their index size/hash. Record dated
   URLs, input hashes, tool identities, signature/validity evidence and limits in
   `reviews/T213/README.md`. Refuse changed candidate input, invalid/expired/revoked
   key/signature, missing artifact/pin and any unreviewed version/substitution.
3. Select only0.4.9.14-1~d12.bookworm+1 in Dockerfile and the two content-lock rows.
   Change only Tor's per-architecture version/hash rows in package-closure.lock.
   Preserve every Debian/base/index/other executable pin; unexpected dependency
   closure drift stops rather than regenerating golden rows. Keep install-tor.sh,
   verify-closure.sh, signing-key rules, live authenticated repository retrieval,
   source isolation, no-download install, torrc, privileges and diagnostics intact.
4. Build the real native amd64 Tor image from the exact candidate with no reused
   Tor build layer. Use the existing VPS and qualified bounded native Docker
   controls; no VM is needed. Prove installed dpkg version, reported Tor version,
   the complete exact package closure, enforcing source/image identities and full
   owned cleanup. Give the build an independently enforced finite deadline and
   retain its failure evidence. Run relevant hermetic Tor/torrc/package-integrity
   contracts. Both architecture artifact identities are verified; do not claim an
   arm64 build/runtime measurement that did not run.
5. Append a dated manual-promotion rationale to SECURITY-DECISIONS.md without
   rewriting historical entries. Append the dated threat-model selection update
   and correct BUILD-DIFFS' active version guidance. Preserve historical0.4.9.13
   measurements, approvals and comments explicitly tied to their original dates;
   do not relabel them as0.4.9.14 evidence. State that moving-index retention remains
   a fail-closed availability limitation and that T212/T202 live closure is pending.
6. Stage the final reports and renewed GREEN, run the complete ordinary canonical
   driver gate, and obtain fresh matching native GLM/Astra implementation approvals.
   Commit only this ticket's declared implementation union; reviewer-scorecard
   belongs only in the normal done follow-up. No push, merge or deployed update.
   T212 subsequently owns its one complete default Docker cadence and DNS
   complement; this ticket does not claim those integrated results or repeat the
   previously delivered T210 standalones separately.

## Analysis

- **Must hold:**
  - Only the selected Tor artifact/version changes; both architecture artifacts
    are independently bound to currently signed official metadata and the
    unchanged Tor signing identity (FR-015; Constitution IV).
  - Existing source isolation, exact local artifact hash checks,
    `--no-download` installation, dependency closure, non-root runtime,
    diagnostics policy and torrc invariants remain intact (T160/T177/T191;
    `contracts/torrc.md`; Constitution V/VI).
  - Build and runtime claims identify their exact inputs and limits; amd64
    native runtime evidence does not imply arm64 runtime qualification
    (Constitution V/VI).
  - The changed integrity expectation fails before implementation and passes
    after it; both matching independent reviewers approve the final candidate
    (Constitution VII/VIII).
- **Gated:**
  - `tor_package_integrity_test.sh` covers both architecture pins, same-version
    substitution, missing pin, failed download, unsupported architecture and
    hostile dependency metadata; `tor_build_inputs_test.sh` and
    `tor_entry_test.sh` protect repository isolation, installer and runtime
    identity controls.
  - `scripts/verify.sh` runs the shell contract suite and Go torrc contracts;
    the bounded native build/runtime observation separately checks installed
    package identity, the complete amd64 closure, torrc bytes and owned cleanup.
- **Residue:**
  - Upstream can remove or replace these artifacts after verification. The
    ticket therefore records dated signed-index and package hashes and retains
    fail-closed behavior (Acceptance #2 and #5); future clean builds still
    require a reviewed refresh.
  - The arm64 artifact is authenticated against its index but is not built or
    run here (Acceptance #4). Its runtime behavior remains unmeasured and must
    not be inferred from amd64 evidence.
  - Native build/runtime and system cleanup evidence is environment-specific;
    exact candidate, image, package closure and cleanup receipts must remain
    bound to the recorded run, with failures preserved rather than relabeled
    (Acceptance #4 and #6).

## Out of scope

No automatic version promotion, security-fix assertion without evidence, dependency
refresh beyond Tor, installer/closure algorithm changes, archival service or vendored
repository, signature/expiry/revocation waiver, policy/constitution amendment, VM,
deployed restart, publication, deleted retained asset, weakened assertion/deadline,
new opt-out/SKIP or reused local-cache claim of clean-CI success. Stop on drift.

## Filing and resumed batch

This ticket is filed and authorized under the plan-v2 and frozen-proposal
decisions recorded in its frontmatter. Filing also records T212's
new prerequisite after exact staged/unstaged preservation and replay proof. T212's
first attempt, START, RED, successful109cold rows, failedT162 and cleanup evidence
remain historical. After T213 delivery, T212 is manually reopened/reset under the
unchanged driver and records its new genuine START; original tests-first JSON is
restored before fresh RED so superseded evidence survives. Reconcile the saved
implementation only after that RED, then identical GREEN. Never force the old
START or copy old proof tokens onto the new candidate.

T202 remains deferred on T212. All existing T212 budget/coverage/Git-history/identity/
cleanup requirements remain; changed-input measurements are renewed, unchanged
component timing can be credited only with explicit complete input comparison.
