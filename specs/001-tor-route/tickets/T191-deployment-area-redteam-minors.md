---
id: T191
title: 'Resolve surviving deployment-area redteam minors and audit gaps'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 3 minors and T155 reconciliation gaps that survived falsification)"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 14
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "VI: Open and Auditable"
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/wire-auth.md
  - specs/001-tor-route/contracts/foundation-boundaries.md
decision_refs:
  - "foundation-boundaries.md:87-90 (T164): verified local build plus local image ID for the observer"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T191: Resolve surviving deployment-area redteam minors and audit gaps

## Context

Surviving items from the 2026-09-29 cumulative redteam area 3 and the T155
reconciliation gaps, after falsification. Falsified or already-accepted items
(Tor version removal per the T099 rotation decision, observer shared UID per
contract, CP exec /tmp per T129) are out of scope except where wording is listed.

## Analysis

- Must hold: each item is fixed with a discriminating check or corrected text;
  no gate records PASS for work that did not run.
- Gated: `scripts/verify.sh`, compose contract tests.
- Residue: items needing a maintainer decision are recorded in SECURITY-DECISIONS.

## Acceptance

1. Observer trust anchor: key rotation (wire-auth §6.2) and init refresh the
   observer's `cp.pub` copy atomically; extend the R9 rotation test to the observer.
2. DP AppArmor: narrow `/proc/**` read to what the Go runtime needs and deny
   `/proc/*/net/**`; prove the DP still starts and host socket tables are denied.
3. Inter-plane R1–R9: skipped runtime rows emit a `SKIP:` line (or become a
   separately accounted gate) so verify.sh never records PASS for them.
4. CI: add a docker-cadence job for sidecar/Dockerfile changes; pin JDK/Python/Node
   exactly; remove or lock-bind the Maven cache.
5. False comments: Dockerfile "digest pinned in compose" claims, init "no outbound
   except image pulls", env example "compose-internal" ports; state the truth
   and where final-image pinning happens (T081).
6. opencode adapter (July finding 010): correct the `scripts/agent-cli/opencode.sh`
   CI-safety comment and the inert `--no-auto` hint; add bash deny rules for the
   CI job or record an explicit maintainer risk acceptance.
7. Remove the orphan CP-writable `stargate-tor-config` mount, volume and init
   step, and update the expected volume set in the compose tests.
8. Stack smoke test: delete the stale T131 compensations in
   `tests/integration/stack_smoke_test.go` (pre-provisioned keys, Tor-first
   bring-up, keys mkdir), relying on the real init path.
9. Observer provenance: add a SECURITY-DECISIONS entry reconciling T138's
   "verified provenance" wording with the T164 local-image-ID model, and name the
   observer image in T081's acceptance.
10. Wording: SECURITY-DECISIONS T099 rotation note says removal happens on every
    Tor release; quickstart avoids shell-history token exposure.

## Out-of-scope

Tor package-closure pinning (T184); Maven lock (T185).
