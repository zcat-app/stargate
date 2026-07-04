---
id: T082
title: 'Amend THREAT-MODEL.md §8.6 to resolve the Tor sidecar maintainer trust'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: derived-from-T017-redteam  # not in tasks.md; filed from T017's redteam MAJOR 2
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T017]   # T017 ships the decision this amendment reflects
parallel: false
files_budget: 2
privacy_critical: true
complexity: low
risk: low
round_cap: 2
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

# T082: Amend THREAT-MODEL.md §8.6 to resolve the Tor sidecar maintainer trust decision

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

- **AT-1 (tests-first, Principle VII).** Add
  `tests/contract/threat-model/sidecar_trust_amend_test.sh` (structural;
  hermetic — grep only). It MUST pass under verify gate 4 and assert:
  - THREAT-MODEL.md §8.6 does NOT contain "unresolved trust decision" or
    "choose a community maintainer" (the stale framing).
  - §8.6 DOES reference `SECURITY-DECISIONS.md` (the authoritative rationale
    location).
  - THREAT-MODEL.md §2.6's internal "See §5.x" pointer cites §5.8 (not §5.7).
- **AT-2.** `scripts/verify.sh` is GREEN.
- **AT-3.** Diff is surgical: only THREAT-MODEL.md (§8.6 + §2.6 pointer) +
  the new contract test. No other spec or artifact touched.

## Out-of-scope

- Re-litigating the build-vs-community-maintainer decision (that is
  resolved in T017 / SECURITY-DECISIONS.md; T082 only syncs the model).
- Amending any other THREAT-MODEL section.
- Editing SECURITY-DECISIONS.md (T017 owns it; T082 only points to it).
- Amending arch §7 (T018's job).

## Notes

- Mirror T018's structure (the arch-§7 sibling amendment) for the
  spec-amend discipline.
- This ticket does NOT exist in tasks.md (it was not in the original
  spec-kit plan). It was filed mid-T017 from a redteam finding; the
  `source:` field records that provenance.
