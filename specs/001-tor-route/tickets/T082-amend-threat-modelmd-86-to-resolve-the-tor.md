---
id: T082
title: 'Reconcile the threat model with the local stack'
status: pending
created: 2026-07-04
last_updated: 2026-07-11
source: review/sol-review.md#M8
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T017, T089, T094, T099]
parallel: false
files_budget: 4
privacy_critical: true
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - THREAT-MODEL.md §8.6 (Sidecar maintainer trust)
  - THREAT-MODEL.md §5.8 (Sidecar compromise — the residual anchor)
  - THREAT-MODEL.md §5.9 (Update channel compromise)
decision_refs:
  - SECURITY-DECISIONS.md §"2026-07-04 — Tor sidecar trust rationale (FR-015)"
constitution_refs:
  - "V: Honest Threat Model"
  - "VI: Open and Auditable"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
spec_amend_for: THREAT-MODEL.md §8.6
spec_amend_parent: T017
---

# T082: Reconcile the threat model with the local stack

## Context

Filed from T017's `stargate-redteam` pass (MAJOR finding 2). T017 ships the
Tor sidecar trust rationale in `SECURITY-DECISIONS.md` and resolves the
trust decision by **building in-house from `deb.torproject.org`** rather
than choosing a community image maintainer. THREAT-MODEL §8.6 currently
frames the decision as unresolved and prescribes the community-maintainer
path; the model and the decision log now contradict (Constitution V —
honest threat model; Constitution VI — open and auditable). T018 amends
arch §7 for the same decision; T082 is the THREAT-MODEL sibling amendment.
**Pre-existing typo at THREAT-MODEL.md:154** ("See §5.7" inside §2.6's prose;
§5.7 is "Browser fingerprinting", the sidecar-residual section is §5.8) is
also corrected here — it is the same Constitution-V "dead pointer" defect
class and was flagged out-of-scope for T017.

## Analysis

*(Required — `privacy_critical: true`.)*

- **Must hold (M1):** §8.6's prose is rewritten so it no longer says
  "unresolved trust decision at the time of writing" or "we must choose a
  community maintainer." It records that the decision IS resolved (build
  in-house from `deb.torproject.org`, fingerprint-verified at build time),
  points to `SECURITY-DECISIONS.md` §"2026-07-04 — Tor sidecar trust
  rationale (FR-015)" as the authoritative rationale, and preserves the
  §5.8/§5.9 residual framing (sidecar-in-TCB + update-channel-compromise).
- **Must hold (M2):** The pre-existing internal cross-ref typo at
  THREAT-MODEL.md:154 ("See §5.7" inside §2.6) is corrected to "See §5.8".
- **Must hold (M3):** No other THREAT-MODEL content is perturbed (surgical
  edit; §8.6 + the §2.6 internal pointer only).
- **Gated:** a contract test under `tests/contract/threat-model/` (new in
  this ticket) asserts §8.6 no longer contains the "unresolved"/"choose a
  community maintainer" phrasing AND references SECURITY-DECISIONS.md; and
  that §2.6's internal pointer cites §5.8 (not §5.7).
- **Residue:** the soundness of the §8.6 rewrite prose is review-gated
  (redteam not mandatory — this is a doc sync of an already-redteam'd
  decision; the redteam on T017 already gated the underlying rationale).

## Acceptance

1. Update status/date and replace false present-tense claims with the topology
   actually delivered by T089/T094/T099: which images/build inputs are pinned,
   which roots/mounts are writable, which service has egress, and whether any
   component can reach Docker API.
2. Resolve §8.6's obsolete community-maintainer language in favor of the
   in-house Tor build and point to the existing decision record.
3. Correct §2.6's sidecar-compromise cross-reference from §5.7 to §5.8 and
   remove every "SECURITY-DECISIONS.md once authored" statement.
4. Replace §9's claim that CONTRIBUTING does not exist with the concrete
   private GitHub Security Advisory route and current pre-release caveat.
5. Add a focused structural consistency test for the load-bearing facts above;
   do not create broad prose regexes that freeze incidental wording.
6. Cross-check the same facts in architecture, Compose, quickstart, and
   `SECURITY-DECISIONS.md`; `scripts/verify.sh` passes.

## Out-of-scope

- Re-litigating the build-vs-community-maintainer decision (that is
  resolved in T017 / SECURITY-DECISIONS.md; T082 only syncs the model).
- Rewriting unrelated per-route threat analysis.
- Editing SECURITY-DECISIONS.md (T017 owns it; T082 only points to it).
- Amending arch §7 (T018's job).

## Notes

- Mirror T018's structure (the arch-§7 sibling amendment) for the
  spec-amend discipline.
- This ticket does NOT exist in tasks.md (it was not in the original
  spec-kit plan). It was filed mid-T017 from a redteam finding; the
  `source:` field records that provenance.
