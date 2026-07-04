---
id: T017
title: 'Author `SECURITY-DECISIONS.md` (new file at repo root) with the Tor si'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T017
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh
parallel: false
files_budget: 3
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"FR-015" (Tor sidecar trust rationale MUST be recorded in SECURITY-DECISIONS.md)
  - specs/000-architecture/spec.md §7 (Sidecar Image Strategy — Tor row, "NEEDS CLARIFICATION" digest pinning; T018 amends in lock-step)
  - specs/000-architecture/spec.md §4.3 (inter-plane key ownership — referenced for cross-plane isolation framing)
decision_refs:
  - specs/001-tor-route/research.md §1 (toolchain pins / digest-pin discipline)
  - sidecars/tor/Dockerfile (apt-key fingerprint verification, debian:12-slim base digest, PUB_COUNT==1 TOFU resistance)
constitution_refs:
  - "IV: Pinned, Tested, Manually Promoted Updates"
  - "VI: Open and Auditable"
  - "VIII: Adversarial Review"
reviews: { round: 2, date: 2026-07-04, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings:
  - "2026-07-04 (3 redteam rounds, converged CLEAN): round 1 FINDINGS (0B/3M/5m/2i) — all 3 MAJORs addressed + re-gated: (1) residual-risk prose now names Tor's transitive dependency closure (libssl3/libevent-2.1/zlib1g/libc6) under Debian's archive key (M10-gated); (2) SECURITY-DECISIONS.md carries a 'Resolves (pending T082 amendment of) THREAT-MODEL §8.6' citation (M9-gated); the §8.6 spec edit itself is filed as follow-up T082; (3) the append-only preamble binds entry-body immutability explicitly (M2-gated, both 'immutable once committed' + 'MUST be rejected'). Round 2 FINDINGS (0B/1M/2m/0i) — the MAJOR-1 fix had introduced a factual error (the 'libssl3 pinned by base digest' mitigation parenthetical was wrong: stage-2 `apt-get install tor` resolves libssl3 fresh from Debian's archive, NOT base-pinned); rewrote the bullet to honestly state NO Stargate-side mitigation reaches runtime libssl3; also tightened the immutability gate to assert 'MUST be rejected' (preamble self-protection) and corrected the §8.6 heading tense. Round 3 CLEAN (0B/0M/0m/1i) — converged; the INFO is a non-blocking future-hardening note (the 'MUST be rejected' grep is file-wide; anchor it to the preamble block when T017a/T081 next edits the test). Accepted residue in §Analysis R1/R3/R5."
clarity_check: {}
---

# T017: Author `SECURITY-DECISIONS.md` (new file at repo root) with the Tor sidecar trust rationale

## Context

Derived from `specs/001-tor-route/tasks.md` T017. Creates the repo-root
`SECURITY-DECISIONS.md` append-only log (the file AGENTS.md, CONTRIBUTING.md
§398, and THREAT-MODEL.md §871/§1173 already reference as the canonical home
for accepted-finding rationales) and writes its first entry: the Tor sidecar
trust rationale mandated by FR-015 ("The trust rationale MUST be recorded in
`SECURITY-DECISIONS.md`"). T017a appends the docker-socket-proxy rationale to
the same file; T081 appends the release-time final-image digest values +
signing/SBOM/rekor entries; T018 amends arch §7's Tor row in lock-step. T017
establishes the file, its append-only conventions, and the Tor entry only.

> **Full task body (verbatim from tasks.md):**
>
> Author `SECURITY-DECISIONS.md` (new file at repo root) with the Tor sidecar trust rationale (FR-015): why `deb.torproject.org` over a fork; the apt-key fingerprint and rotation policy; the Debian-slim and final-image digest values; and a section reserved for adversarial-review findings from Phase N. (The docker-socket-proxy trust rationale is a separate concern from C1 remediation and lives in T017a, which appends to the same file.)

## Analysis

Property map (per `docs/process/analysis.md`), grounded against FR-015,
`sidecars/tor/Dockerfile` (the build that realises the trust model),
`sidecars/tor/apt-key.fingerprint`, arch §7, THREAT-MODEL §2.3/§2.6, and the
existing cross-references in AGENTS.md / CONTRIBUTING.md / THREAT-MODEL.md.

### Must hold

- **M1 — File + location.** `SECURITY-DECISIONS.md` exists at the repository
  root. Markdown; carries the SPDX header (consistency with the rest of the
  repo, even though `scripts/check-license-headers.sh` does not scan `.md`).
- **M2 — Append-only convention documented.** The file's preamble states its
  purpose (append-only log of accepted-finding rationales + supply-chain
  trust decisions) and the append discipline (Blocker/Major accepted findings
  get an entry; nothing is ever deleted, only superseded with a dated note).
  This locks the contract T017a, T081, and future features append to.
- **M3 — Tor entry: rationale (FR-015).** The Tor sidecar entry states WHY
  Stargate builds from `deb.torproject.org` rather than (a) an upstream
  community Docker image or (b) a forked/distro-shipped `tor`. The honest
  framing: the Tor Project publishes no official Docker image; the official
  Debian apt repo is the Tor Project's own distribution channel; building
  from it on a pinned Debian-slim base is the closest available analogue to
  "the Tor Project's own distribution" (THREAT-MODEL §2.6 — sidecar is in the
  per-route privacy TCB).
- **M4 — Tor entry: apt-key fingerprint + rotation policy.** The entry
  records the pinned fingerprint `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`
  (matching `sidecars/tor/apt-key.fingerprint` exactly), cites the
  Dockerfile's build-time verification (fingerprint match + `PUB_COUNT==1`
  TOFU-resistance assertion), and states the rotation policy: when the Tor
  Project rotates the signing key, every Tor-sidecar build fails loudly
  (intended); the rotation is a manual, review-driven update of
  `apt-key.fingerprint` + this entry + the Dockerfile in one PR.
- **M5 — Tor entry: Debian-slim base digest.** The entry records the pinned
  base digest `sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df`
  (`debian:12-slim`, multi-arch OCI index), matching the `FROM` directives in
  `sidecars/tor/Dockerfile` (both stages) exactly. Resolved via
  `docker buildx imagetools inspect` (registry-direct).
- **M6 — Tor entry: final-image digest (PLACEHOLDER, T081).** The entry does
  NOT invent a final-image digest. It records honestly that the three
  Stargate-built final images (`stargate-dp`, `stargate-control`, `stargate/tor`)
  are NOT yet digest-pinned in compose (T015 ships them as `build:` directives
  for the Phase-2 scaffolding horizon), and that final-image digest pinning +
  cosign keyless signing + SBOM + rekor transparency log entry land at release
  tag time via T081's `release.yml`. This is the literal text of FR-015's
  "final composed image MUST be pinned by sha256 digest" — currently unmet,
  release-blocking, tracked by T081. The entry must not paper over this gap.
- **M7 — Reserved adversarial-review section.** The file declares a section
  reserved for `stargate-redteam` / `stargate-perf` findings (Constitution
  VIII) and accepted-finding rationales from Phase N+ reviews. Initially empty
  (a placeholder heading + the append convention), populated by later
  tickets/features as findings are accepted. (Constitution VIII row in
  `spec.md` already states findings "either resolved or recorded in
  SECURITY-DECISIONS.md".)
- **M8 — Scope boundary.** The docker-socket-proxy rationale is NOT in T017's
  entry (T017a appends it). The arch §7 amendment is NOT in T017 (T018 does
  it). T017 does not duplicate the torrc contract, the SOCKS5 contract, or
  THREAT-MODEL content — it cites them.

### Gated (verify.sh catches fail-closed)

- **G1** — New structural contract test
  `tests/contract/security-decisions/tor_entry_test.sh` (verify gate 4,
  auto-discovered) → M1 (file exists at root), M3 (rationale keywords
  present), M4 (fingerprint present AND cross-equals
  `sidecars/tor/apt-key.fingerprint`), M5 (base digest present AND
  cross-equals the `sidecars/tor/Dockerfile` FROM digest), M6 (final-image
  entry references T081 / release-tag — does NOT assert a fake digest),
  M7 (adversarial-review section heading present), M8 (no
  docker-socket-proxy entry — that's T017a's append). The cross-file checks
  (fingerprint, base digest) promote drift-detection into the gate:
  editing the Dockerfile's pin without updating SECURITY-DECISIONS.md (or
  vice versa) fails the test.

### Residue (no gate catches — redteam focus)

- **R1 — Rationale prose correctness.** The "why deb.torproject.org over a
  fork" argument is prose; G1 asserts keyword presence, not that the
  argument is sound or complete. **Downstream gate:** review + redteam
  (this ticket is `privacy_critical: true` → redteam fires). The redteam is
  the correctness gate for the trust argument itself. **(Materialized at
  redteam round 1: MAJOR 1 — the residual-risk prose omitted Tor's
  transitive dependency closure (libssl3 et al.) under Debian's archive
  trust. Fixed in this ticket: added a dedicated residual bullet naming
  libssl3 as the single most security-relevant TCB component sitting outside
  the fingerprint-verified channel.)**
- **R2 — Final-image digest gap.** M6's placeholder is honest but the gap
  is real and release-blocking per FR-015's literal text. **Downstream
  gate:** T081 (release.yml GHCR push + cosign + SBOM + append-back to
  this file). G1 asserts the placeholder references T081, not that the
  digest exists.
- **R3 — Future-append discipline.** G1 locks the file's shape NOW; it
  cannot prevent a future feature from appending a poorly-justified entry
  or silently editing an existing one. **Downstream gate:** review on each
  appending PR + the CONTRIBUTING.md §398 norm. **(Hardened at redteam
  round 1: MAJOR 3 — the preamble's immutability rule was scoped only to
  the supersede path, permitting silent in-place weakening of an entry's
  body. Fixed in this ticket: the preamble now binds entry-body
  immutability explicitly — any change MUST land as a superseding entry;
  the contract test gates the clause's presence. Residual R3 now reduces
  to "review enforces the immutability rule on PRs that touch dated
  entries," which is the standard review burden.)**
- **R4 — Fingerprint / digest liveness.** The cross-file check proves the
  three locations agree, NOT that the fingerprint/digest is currently
  valid against the upstream (the Tor Project may have rotated the key,
  debian may have re-pushed the tag). **Downstream gate:**
  `scripts/ground-check.sh` online mode resolves the Dockerfile's base
  digest at release cadence (T081 AT-1 makes it release-mandatory); the
  apt-key fingerprint is verified live at every Tor-sidecar BUILD (the
  Dockerfile's `curl … ${EXPECTED_FPR}.asc` + gpg check fails the build
  if the upstream key no longer matches). So R4 is caught at build/release
  cadence, not at PR cadence.
- **R5 — THREAT-MODEL §8.6 drift (from redteam round 1, MAJOR 2).** T017
  resolves §8.6's "unresolved trust decision" by building in-house, not by
  choosing a community maintainer; the model and the decision log now
  contradict (Constitution V). T017's half (the "Resolves/supersedes
  THREAT-MODEL §8.6" citation in SECURITY-DECISIONS.md) is fixed in this
  ticket + gated by the M9 contract assertion. The THREAT-MODEL §8.6 spec
  edit itself is out of T017's scope (would be a drive-by edit to a merged
  artifact); filed as follow-up **T082** (sibling to T018).

## Acceptance

- **AT-1 (tests-first, Principle VII).** Add
  `tests/contract/security-decisions/tor_entry_test.sh` (structural +
  cross-file contract test; hermetic — no network, no daemon, just file
  reads + grep + diff against artifact files). It MUST pass under verify
  gate 4 and assert, at minimum:
  - `SECURITY-DECISIONS.md` exists at the repo root and carries the SPDX
    header (M1).
  - **Append-only convention (M2):** a preamble stating the file's
    append-only purpose is present.
  - **Tor rationale (M3):** the Tor entry references `deb.torproject.org`
    AND explains the build-vs-fork/upstream choice (keywords present).
  - **Apt-key fingerprint (M4) + cross-file:** the fingerprint
    `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89` appears in
    SECURITY-DECISIONS.md AND equals the contents of
    `sidecars/tor/apt-key.fingerprint` (whitespace-trimmed). Drift fails.
  - **Base digest (M5) + cross-file:** the debian:12-slim digest
    `sha256:60eac759...` appears in SECURITY-DECISIONS.md AND equals the
    `FROM debian:12-slim@sha256:...` digest in `sidecars/tor/Dockerfile`
    (both stages). Drift fails.
  - **Final-image digest honesty (M6):** the entry references T081 /
    release-tag-time pinning AND does NOT assert a final-image sha256
    digest as if it were already pinned (the test asserts the file does
    not contain a fabricated `stargate/tor@sha256:`-style final-image pin
    presented as current).
  - **Adversarial-review section (M7):** a reserved section heading for
    redteam/perf findings is present.
  - **Scope boundary (M8):** the file does NOT contain a docker-socket-proxy
    rationale entry (that's T017a's append — its absence here is the
    scope-boundary signal).
- **AT-2.** `scripts/verify.sh` is GREEN (the new contract test passes; no
  existing gate regresses).
- **AT-3 (residue acknowledgement, non-blocking).** §Analysis R1–R4 each
  map to a named downstream gate (redteam for R1, T081 for R2, review for
  R3, build/release-cadence for R4).

## Out-of-scope

- **The docker-socket-proxy trust rationale** — T017a appends it to this
  same file. T017 MUST NOT include it (its absence is gated by AT-1 M8).
- **The arch §7 amendment** (removing the Tor row's "NEEDS CLARIFICATION"
  marker once the base + final-image pinning lands) — T018 does this in
  lock-step. T017 cites §7 but does not edit the arch spec.
- **Final-image digest values** for the three Stargate-built images — T081
  produces them at release tag time (GHCR push + cosign). T017 records the
  BASE-image digest only and marks the final-image gap honestly (M6).
- **Nym / i2pd / WireGuard sidecar entries** — those sidecars are not in
  this feature. Their SECURITY-DECISIONS.md entries ship with their
  respective feature specs.
- **Any contract test for the docker-socket-proxy entry** — T017a's job.
- **Editing `scripts/check-license-headers.sh`** to scan `.md` files. The
  SECURITY-DECISIONS.md SPDX header is asserted by AT-1 directly; expanding
  the license gate's scope is a separate concern (would touch every `.md`
  in the repo).

## Notes

- **File format / append conventions:** model on a dated-entry append-only
  log. Each entry: a `## <YYYY-MM-DD> <topic>` heading, a "Decision" line,
  a "Rationale" paragraph, a "Residual risk" paragraph, and (when
  applicable) a "Superseded by" line that future entries set rather than
  deleting prior content. T017a, T081, and future features append `##`
  entries below; they do not edit the Tor entry except to add a
  "Superseded by" note.
- **Fingerprint source of truth:** `sidecars/tor/apt-key.fingerprint`
  (single line, no whitespace). SECURITY-DECISIONS.md quotes it verbatim;
  the contract test cross-checks. The Dockerfile reads the same file at
  build time. Three locations, one value, gated.
- **Base digest source of truth:** `sidecars/tor/Dockerfile` `FROM` lines
  (both stages use the same digest). `scripts/subcommands/init`'s
  key-gen helper reuses the same digest (T016 R5). SECURITY-DECISIONS.md
  records it for human auditability; the contract test cross-checks.
- **Why no final-image digest now:** compose (T015) ships the three
  Stargate-built images as `build:` directives; there is no registry push
  in the Phase-2 scaffolding horizon, so no final-image digest exists to
  pin. T081's `release.yml` is the gate that produces and writes back
  those digests. Recording a fabricated value here would violate the
  "honest threat model" Principle V.
- **THREAT-MODEL cross-refs to cite in the Tor entry:** §2.3 (active
  network adversary — the build-time MITM the PUB_COUNT==1 assertion
  defeats), §2.6 (compromised sidecar — Tor is in the per-route privacy
  TCB), §5.8 (sidecar compromise — the residual-risk anchor). These anchor
  the rationale to existing model text rather than re-deriving it. **Note:**
  THREAT-MODEL.md:154 has a pre-existing internal typo ("See §5.7" inside
  §2.6's prose; §5.7 is actually "Browser fingerprinting", the
  sidecar-residual section is §5.8). T017 cites §5.8 correctly; the
  THREAT-MODEL typo is a separate follow-up ticket (out of T017's scope —
  do not drive-by edit a merged artifact).
- **References:** FR-015 (spec.md), arch §7 (Tor row), THREAT-MODEL §2.3 /
  §2.6 / §5.8, `sidecars/tor/Dockerfile`, `sidecars/tor/apt-key.fingerprint`,
  CONTRIBUTING.md §398, AGENTS.md SECURITY-DECISIONS row.
