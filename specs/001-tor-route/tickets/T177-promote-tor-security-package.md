---
id: T177
title: 'Promote Tor 0.4.9.13 security package'
status: in-review
created: 2026-09-26
last_updated: 2026-09-26
source: https://forum.torproject.org/t/security-release-0-4-9-13/22178
phase: 'Urgent security update'
story: '-'
blocked_by: ["T160"]
parallel: false
files_budget: 10
files_scope:
  - specs/001-tor-route/tickets/T177-promote-tor-security-package.md
  - specs/001-tor-route/tickets/T124-tor-healthcheck-bootstrap-window-shor.md
  - specs/001-tor-route/STATUS.md
  - sidecars/tor/Dockerfile
  - sidecars/tor/tor-packages.sha256
  - tests/contract/security-decisions/tor_package_integrity_test.sh
  - THREAT-MODEL.md
  - BUILD-DIFFS.md
  - SECURITY-DECISIONS.md
  - specs/001-tor-route/evidence/T177-tests-first.json
  - reviews/T177/README.md
privacy_critical: true
tests_first: []
constitution_refs:
  - 'III: Privacy-Preserving by Construction'
  - 'IV: Pinned, Tested, Manually Promoted Updates'
  - 'V: Honest Threat Model'
  - 'VII: Tests-First for Privacy-Critical and Contract Code'
  - 'VIII: Adversarial Review at Milestones'
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md FR-015/FR-016
  - specs/001-tor-route/contracts/torrc.md
decision_refs:
  - SECURITY-DECISIONS.md T160 Tor package promotion
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T177: Promote Tor 0.4.9.13 security package

## Context

T124's disposable-host fresh-volume `init` could not build the Tor sidecar:
the Tor Project's current Bookworm index no longer offered the repository's
checked `0.4.9.12-1~d12.bookworm+1` package. On 2026-09-23 Tor announced
0.4.9.13 as a high-severity security release and recommended prompt upgrades.
This ticket is the separate, reviewed package promotion needed before T124 can
obtain its required live evidence. It does not reopen T160's approved commit.

## Analysis

- **Must hold:** the selected amd64/arm64 packages come from the official
  Bookworm repository, with authenticated, current Release metadata and
  package identities checked against an independent content lock before
  installation. The signed mutable index alone is insufficient (IV).
- **Must hold:** only the Tor package changes. Preserve the Debian snapshot,
  verified signing-key fingerprint, checked local-file install, dependency
  source isolation, non-root runtime, exact torrc bytes and suppressed raw
  diagnostics (III/IV).
- **Gated:** the existing package-integrity contract exercises both
  architectures, same-version substitution, missing pins, failed download,
  unsupported architecture and hostile dependency metadata. A new version
  expectation must fail against the existing Dockerfile and lock before the
  implementation (VII).
- **Residue:** a hermetic fixture cannot authenticate today's repository
  metadata, prove real package hashes or establish native image behavior.
  Ground and retain those results separately. T124 owns the fresh-volume
  integrated READY run; this ticket does not claim it.

## Acceptance

1. Before changing the Dockerfile or lock, update the existing contract to
   expect the official `0.4.9.13-1~d12.bookworm+1` package and record its
   failing result through `scripts/test-first-evidence.py`. Preserve all
   T160 negative controls. Record the identical probe's green result after
   implementation.
2. Verify the official Bookworm InRelease signature and validity against the
   existing pinned primary key; confirm both architecture Packages files'
   hashes against the signed Release, then actual amd64/arm64 `.deb` hashes
   against Packages. Update the two content-lock rows to those independently
   checked bytes. Record dated URLs, signatures, hashes and limitations in
   `reviews/T177/README.md`.
3. Select only the new checked package in `sidecars/tor/Dockerfile`. Keep
   `install-tor.sh`, the Debian snapshot and all other executable pins,
   architecture checks, source isolation, `--no-download` install, base
   digest, signing-key rule, torrc bytes, runtime privileges and diagnostics
   behavior unchanged. Build the native Tor image and verify its installed
   package version and reported Tor version. Run relevant Tor contracts.
4. Append the promotion rationale to `SECURITY-DECISIONS.md` without rewriting
   prior entries; add the scoped supersession back-link on the historical T160
   entry. Reconcile `BUILD-DIFFS.md` auditor guidance with the current lock,
   and add a dated threat-model update that distinguishes the new artifact
   from T160's historical evidence. Mark T124 dependent on T177 and regenerate
   STATUS. No deployed image is silently promoted.
5. Run `bash scripts/verify.sh` on the exact staged candidate, obtain both
   native independent reviewer approvals through the normal T177 driver,
   and commit one focused ticket change. T124's subsequent fresh-volume run
   remains a separate acceptance gate.

## Out-of-scope

No constitution or torrc amendment, Debian dependency refresh, automatic
update, deployed-stack restart, publication, Tor availability claim or
changes to T124's 300-second READY policy. Do not weaken a test or pin to
force an image build.

## Notes

The failed T124 run and diagnostic build are preserved in T124's stashed
in-progress candidate; its evidence report will land with that ticket. The
upstream announcement is https://forum.torproject.org/t/security-release-0-4-9-13/22178.
