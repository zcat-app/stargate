---
id: "T140"
title: "Enforce Tor package content integrity pins"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T099", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T099"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T140: Enforce Tor package content integrity pins

## Context

Existing finding 20260727-002: the Tor content hash is prose, while the build installs a named version from the live repository; package-name/version equality misses content replacement.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Ground the recorded hashes against the supported architecture artifacts; specify which verified bytes the build consumes.
2. Write a negative build-contract fixture with same package name/version but changed bytes; installation must fail before the altered artifact is used.
3. Enforce the content pin without removing upstream signature verification or Debian snapshot pins; record architecture-specific inputs and update instructions.
4. Run targeted build-contract tests and scripts/verify.sh; distinguish content integrity from best-effort final-image reproducibility (Constitution IV/VI).

## Out-of-scope

Automatic component promotion, unreviewed dependency updates, or claiming a byte-stable final image.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
