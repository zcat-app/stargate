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

*(Required — `privacy_critical: true`. Grounded 2026-08-22; all anchors
verified on disk.)*

**Grounded facts** (what T089/T094/T099 actually deliver, per
`compose/docker-compose.local.yml`, `sidecars/tor/Dockerfile`,
`SECURITY-DECISIONS.md`:664, constitution V/VI):

- Networks: three-way split — `stargate-egress` (non-internal, Tor only),
  `stargate-internal` (internal:true, DP↔tor), `stargate-cp-tor`
  (internal:true, CP↔tor); planes share no network.
- All services `read_only: true`, `cap_drop: [ALL]`; no service mounts
  `/var/run/docker.sock` (T094a dropped the docker-socket-proxy; M4 gates it).
- Pinning: base image digest-pinned (both stages); Debian package inputs
  pinned to immutable snapshot run `20260714T082229Z` with explicit
  `=version` pins (T099); `tor` installed from `deb.torproject.org` with
  build-time signing-key fingerprint verification (`PUB_COUNT==1`,
  fingerprint `A3C4…DD89`). Final composed image digests are NOT yet pinned
  (T081 pending) — must not be claimed as pinned.
- **Honesty constraint:** open finding
  `redteam/findings/open/20260727-002-tor-deb-hash-never-verified.md`
  (status: open): the recorded tor `.deb` sha256 is verified by no build
  step. The §8.6 rewrite must NOT claim content-hash enforcement of the
  tor package — only claims that actually hold (digest-pinned base,
  snapshot-pinned Debian inputs, key-fingerprint-verified signed repo,
  version pin), with same-version-replacement attributed to maintainer
  trust until that finding closes.

Property map:

- **Must hold (M1):** §8.6's prose is rewritten so it no longer says
  "unresolved trust decision at the time of writing" or "we must choose a
  community maintainer." It records that the decision IS resolved (build
  in-house from `deb.torproject.org` on a digest-pinned base), states the
  pinning/key-verification topology that actually holds (per grounded facts
  above — including final-image digests not yet pinned), points to
  `SECURITY-DECISIONS.md` §"2026-07-04 — Tor sidecar trust rationale
  (FR-015)" as the authoritative rationale, and preserves the §5.8/§5.9
  residual framing (sidecar-in-TCB + update-channel-compromise).
- **Must hold (M2):** The pre-existing internal cross-ref typo in §2.6
  (THREAT-MODEL.md:160, "See §5.7" — §5.7 is Browser fingerprinting; the
  sidecar-residual section is §5.8) is corrected to "See §5.8".
- **Must hold (M3):** No other THREAT-MODEL content is perturbed (surgical
  edits: §8.6 rewrite; §2.6 pointer; the two stale-authorship statements —
  §5.8:983 "(once authored)" and §9:1425 "(not yet authored…)"; §9 rewritten
  to the concrete GitHub Security Advisory route that CONTRIBUTING.md:49
  now provides).
- **Gated:** a contract test under `tests/contract/threat-model/` (new in
  this ticket) asserts structurally: §8.6 contains neither obsolete
  phrasing ("unresolved trust decision", "choose a community maintainer")
  nor a claim that final image digests are already pinned, and cites the
  SECURITY-DECISIONS entry title; §2.6's sidecar paragraph cites §5.8 (not
  §5.7); zero "(once authored)"/"not yet authored" strings remain; §9
  references the private GitHub Security Advisory channel. Focused,
  load-bearing assertions only — no broad prose regexes freezing incidental
  wording (acceptance #5).
- **Residue:** the soundness of the §8.6 rewrite prose is review-gated
  (redteam not mandatory — this is a doc sync of an already-redteam'd
  decision; the redteam on T017 already gated the underlying rationale).
  The tor `.deb` hash-verification gap remains tracked by finding
  20260727-002, out of scope here (T082 must not paper over it).

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
