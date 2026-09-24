---
id: "T141"
title: "Pin CI Actions and agent installation dependencies"
status: done
created: "2026-09-12"
last_updated: 2026-09-24
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T096", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T096"
tests_first: []
reviews: { round: 2, date: 2026-09-24, verdict: APPROVE-WITH-FIXES }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T141: Pin CI Actions and agent installation dependencies

## Context

Existing findings 20260727-005/006: executable Actions use mutable tags and agent installers use floating releases in credential-bearing jobs.

## Analysis

- Must hold: external Action code resolves to a full reviewed commit; the
  agent CLIs resolve to exact release archives whose downloaded bytes are
  checked before extraction. Installer processes do not receive the provider
  key. These are Constitution IV/VI build-input properties.
- Gated: `tests/contract/workflow/ci_inputs_test.sh` audits every workflow and
  composite Action and runs negative fixtures for mutable `uses:`, downloaded
  shell installers, unversioned package commands and missing archive checks.
  `scripts/verify.sh` discovers and runs that contract test.
- Residue: a pinned upstream publisher or CI runner can still be malicious;
  the test cannot prove publisher trust or agent containment (T142). Manual
  release review and the normal independent ticket gate cover that residue.

## Acceptance

1. Inventory external Actions and agent CLI installation inputs; pin exact reviewed versions/commit identities and verify downloaded executable artifacts.
2. Add negative fixtures rejecting mutable external uses references, floating curl installers and unversioned package installations; exempt local uses references explicitly.
3. Keep job permissions minimal and ensure installer changes do not broaden credential exposure; obtain upstream identities through primary sources during grounding.
4. Run workflow contract checks and scripts/verify.sh; document manual pin-update procedure under Constitution IV/VI.

## Out-of-scope

Publishing workflow execution, provider changes, secrets rotation, or claiming pinning alone confines the executing agent (T142).

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

### Tests-first evidence (2026-09-24)

`bash tests/contract/workflow/ci_inputs_test.sh` failed before the workflow
edits (saved locally at `target/runs/T141-red.log`). It named all 12 mutable
external `uses:` references, the `curl | bash` installer, the unversioned
`npm install -g`, and the missing pre-extraction archive checks. The pins
were obtained from the upstream GitHub tag refs, the OpenCode release asset
digest, and the npm registry integrity for the Claude Linux x64 package.

Round-2 regression evidence: the added continued-pipeline fixture failed
against the original single-line scanner (`target/runs/T141-r2-red.log`). The
revised contract now discovers `.yml`/`.yaml` workflow and nested Action
files, rejects the continued pipeline and comment-disabled checksum, and
executes each installer body with local good and tampered archives to check
that extraction occurs only after a successful hash check. The corrected
gitleaks pin is the tag's dereferenced commit, confirmed by the publisher's
commit endpoint.
