---
id: T018
title: 'Amend `specs/000-architecture/spec.md` in lock-step: §4.3 inter-plane '
status: done
created: 2026-07-04
last_updated: 2026-07-05
source: tasks.md#T018
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: { round: 2, date: 2026-07-05, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T018: Amend `specs/000-architecture/spec.md` in lock-step: §4.3 inter-plane 

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Amend `specs/000-architecture/spec.md` in lock-step: §4.3 inter-plane socket bullet already replaced (during /speckit-analyze remediation, finding F6) with the two-socket / mode-0660 / per-plane-UID topology — verify at implementation time that the rendered compose / Dockerfile UIDs match (`stargate-cp` 5101, `stargate-dp` 5102, `stargate-ipc` GID 5100); §5.5 last paragraph (snapshot contents) updates to strike "+ route enable/disable mask" — the snapshot is **token-list-only** per `data-model.md` §1.4 / §2, and DP cold-start unconditionally begins DISABLED until the first `HEALTHY` event arrives; replace the struck phrase with a cross-reference to `data-model.md` §1.4 / §2 so future readers don't re-introduce the mask into the snapshot; §6.5 `audit_log.action` enum already extended (during /speckit-analyze remediation, finding F4) to include `config_error`, `sidecar_healthy`, `sidecar_unhealthy` — verify at implementation time that the enum still matches `data-model.md` §4 and that every action this feature inserts is listed; §7 Tor row updates to drop the `NEEDS CLARIFICATION` and reference FR-015's image-provenance pin; §10.1 already extended (during /speckit-analyze remediation, finding C6) with a `SOCKS5 reply` column populating AUTH_REQUIRED (sub-negotiation `0x01 0xFF` per RFC 1929 §2), ROUTE_DOWN/DISABLED (REP `0x03`), ROUTE_REFUSED (REP `0x04`), ROUTE_TIMEOUT (REP `0x06`), and BIND_REFUSED (n/a) — verify at implementation time that the rendered SOCKS5 bytes from `data-plane/internal/socks5/` match the table and that `contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"` has not drifted; §10.3 step 2 updates to change "four permitted fields" to "three permitted fields" (matches `contracts/error-template.md` §"Response body" placeholder list — `{ROUTE_LABEL}`, `{CODE}`, `{LOCAL_REFERENCE_ID}`; the off-by-one came from conflating literal template chrome with substitutions, surfaced by /speckit-analyze finding F12); §14.4 (token storage path) — the `NEEDS CLARIFICATION` marker is already resolved-for-v1 by FR-019 + `research.md` §6 (`storage.local` with the canonical UX warning text pinned in `data-model.md` §5.1); T018 propagates that resolution into arch by stripping the marker and adding the cross-reference; §15 #6 (`Manifest version`) — the open question is resolved-for-v1 per `research.md` §2's follow-up; T018 propagates by marking §15 #6 resolved with a maintenance entry that we re-verify MV2 support on each Mullvad Browser major-version bump; new §16 "Auxiliary Infrastructure Containers" already added (during /speckit-analyze remediation, finding C7) covering the docker-socket-proxy trust model — verify at implementation time that the compose service name, image digest, and proxy environment lockdown (`EVENTS=1`, `CONTAINERS=1`, `POST=0`) match the description and that T017a's `SECURITY-DECISIONS.md` entry remains the authoritative rationale.

## Analysis

Built at `/start` (privacy-critical: the §16.1 reconciliation is a
Constitution V honesty fix — the prior handoff filed the two stale
points as a known, tracked gap; closing it lands here). Grounded
against `specs/000-architecture/spec.md` @ HEAD, the cited feature
anchors, and `docker image inspect` re-verification of the tecnativa
image (carrying-forward lesson from T017a r2 — re-verify upstream
artifact facts rather than copy prose blindly).

### Must hold

- **M1 — §4.3 UID/GID claim already matches the rendered compose.**
  Verified at `/start`: `compose/docker-compose.local.yml` lines
  `user: "5101:5100"` (CP) and `user: "5102:5100"` (DP); `local.env.example`
  line 13 documents the same triple. NO prose edit needed at §4.3 (the
  /speckit-analyze F6 remediation already landed); T018 only verifies the
  match still holds.
- **M2 — §5.5 line ~316-318**: the snapshot-description paragraph currently
  reads "caches the last successful `StatusResponse → token list + route
  enable/disable mask` on disk." The "+ route enable/disable mask" phrase
  is FALSE — `routeEnableMask` is deliberately NOT in the snapshot (data-
  model.md §1.4 line 131 + §2 state machine: cold-start unconditionally
  begins DISABLED). T018 MUST strike the phrase and replace it with a
  cross-reference to data-model.md §1.4 / §2 so a future reader does not
  re-introduce the mask into the snapshot.
- **M3 — §6.5 line 391**: the `audit_log.action` enum is already extended
  (finding F4 remediation landed) to `enrolled, revoked, config_error,
  sidecar_healthy, sidecar_unhealthy, sidecar_restart, bridge_toggle,
  export, import, wipe`. T018 verifies the rendered enum matches data-
  model.md §4 AND that every action this feature inserts (`config_error`,
  `sidecar_healthy`, `sidecar_unhealthy`, `sidecar_restart`) is listed.
  No prose edit needed at §6.5 unless the verification fails.
  **Round-2 rework (codereview F1):** verification FAILED at /start but
  was not acted on honestly. data-model.md §4 enumerates exactly FIVE
  actions inserted by this feature (`enrolled, revoked, config_error,
  sidecar_healthy, sidecar_unhealthy`) — `sidecar_restart` is NOT among
  them (T036 AuditLogService: "five fixed-vocabulary actions"; T074
  makes RESTARTED event-only and explicitly does NOT write an audit-log
  row). The §6.5 line 399 enum comment carried a spurious `sidecar_restart`
  entry (pre-existing paperwork drift from the F4 remediation). T018
  REMOVES the spurious entry from §6.5 so the rendered enum matches
  data-model.md §4 exactly. V001__init.sql line 67 carries the same
  spurious entry; filed as a follow-up (out of T018 scope — T012 owns
  the SQL migration; touching it here would be a drive-by edit).
- **M4 — §7 Tor row line 415**: the Digest-pinning cell still reads
  "`NEEDS CLARIFICATION` — pin both the Debian-slim base and the final
  composed image at first release tag". T018 MUST drop the marker and
  replace it with a reference to FR-015's image-provenance pin (Stargate-
  built image, sha256-pinned Debian-slim base + final image, apt-key
  fingerprint verified at build time, trust rationale in
  `SECURITY-DECISIONS.md`). Concrete digests are already pinned by T014 /
  T015 and cross-checked by T017 / T015 contract tests; the arch spec
  points at those, not at the digest values themselves (those live in
  `compose/env/local.env.example` + `sidecars/tor/Dockerfile` + the apt-
  key fingerprint file, the canonical sources).
- **M5 — §10.1 table lines 564-571**: SOCKS5 reply column is already
  populated (finding C6 remediation landed). T018 verifies the column
  matches `contracts/socks5-auth.md §"SOCKS5 request-phase failures
  (post-auth)"` (REP `0x03` for ROUTE_DOWN/DISABLED, `0x04` for
  ROUTE_REFUSED, `0x06` for ROUTE_TIMEOUT, AUTH_REQUIRED sub-negotiation
  `0x01 0xFF`, BIND_REFUSED n/a). No prose edit needed unless the
  verification fails.
- **M6 — §10.3 step 2 line 604-605**: currently says "Body matches the
  template byte-for-byte after substitution of the **four** permitted
  fields." This is the off-by-one surfaced by /speckit-analyze F12 —
  `contracts/error-template.md §"Response body"` lists exactly THREE
  substitution tokens (`{ROUTE_LABEL}`, `{CODE}`, `{LOCAL_REFERENCE_ID}`);
  the fourth came from conflating literal template chrome with
  substitutions. T018 MUST change "four" → "three".
- **M7 — §14.4 line 871-874**: the closing paragraph currently reads
  "…otherwise in `storage.local` with a clear UX warning. `NEEDS
  CLARIFICATION`: which storage path Mullvad Browser exposes for
  credential-grade secrets." This is resolved-for-v1 by FR-019 +
  research.md §6 (Firefox ESR exposes no credential-grade storage API;
  `storage.local` accepted with the canonical warning pinned in
  data-model.md §5.1). T018 MUST strip the `NEEDS CLARIFICATION` marker
  and add the cross-reference to FR-019 + research.md §6 + data-model.md
  §5.1.
- **M8 — §15 #6 line 941-943**: open question "Confirm MV2 support on
  Mullvad Browser at v1 release window…". Resolved-for-v1 per research.md
  §2 (Firefox ESR continues to ship MV2 + `proxy.onRequest`; no MV3
  migration path preserves per-request routing; assume MV2 throughout v1
  release window). T018 MUST mark §15 #6 resolved with a maintenance
  entry: re-verify MV2 support on each Mullvad Browser major-version bump.
- **M9 — §16.1 line 994 (drift fix #1, filed in T017a r3 MAJ-1)**: the
  Mitigations paragraph currently lists "proxy runs as the unprivileged
  user its upstream image declares." Re-verified at `/start` via
  `docker image inspect tecnativa/docker-socket-proxy:0.3.0@sha256:…`
  → `Config.User` is empty = the proxy runs as root. The clause is FALSE.
  T018 MUST delete it AND replace it with the honest "no defense-in-depth
  user-isolation control exists; the proxy runs as root — see
  `SECURITY-DECISIONS.md` docker-socket-proxy entry Mitigation #1"
  framing, matching the entry's r2-MAJOR-2 fix verbatim in spirit.
- **M10 — §16.1 line 998-1004 (drift fix #2, filed in T017a r3 MAJ-1)**:
  the Profile-applicability paragraph currently narrows the release-
  blocker to CP only ("The LAN and VPS profiles expose the CP to non-
  localhost callers…"). T018 MUST widen it to CP/DP/Tor to match T017a's
  Release-blocker paragraph (the DP is the most concerning pivot since
  it faces internet-supplied input the CP does not; Tor is also a
  reacher). T017a's `docker_socket_proxy_entry_test.sh` M9 gates the
  positive "Release-blocker paragraph names DP + Tor" assertion — until
  T018 lands, that contract test is satisfied by the SECURITY-DECISIONS.md
  entry alone (entry-block-scoped, not arch-spec-scoped), so T018 landing
  the §16.1 fix is what brings the arch spec into lock-step.
  **Redteam r1 widening (MAJ-2):** the §16.1 "Property bought" sibling
  paragraph immediately above was also CP-only and T017a's entry-side
  Property-bought paragraph was deliberately widened to "the same
  property holds for the DP and Tor" (entry line 71) — naming the DP
  explicitly so an auditor does not conclude "the proxy isolates only
  the CP." T018 widens the §16.1 Property-bought paragraph in lock-step
  (same fix shape one paragraph earlier in the same section). The
  r1→r2→r3 T017a pattern held: each round catches a fix-incomplete
  defect one paragraph-sibling further out.
- **M11 — §7 "Outstanding follow-up for the Tor row" sibling paragraph
  (redteam r1 MAJ-1):** T018's M4 amendment sharpened the §7 Tor-row
  cell to "The trust rationale is in `SECURITY-DECISIONS.md` (T017)".
  The sibling paragraph 11 lines below still read "the trust-rationale
  narrative required by Principle IV must land in SECURITY-DECISIONS.md
  once that file is authored" — verifiably false (T017 entry exists
  with full rationale; constitution Sync Impact Report no longer lists
  the file as TODO). T018 rewrites the sibling to point at the existing
  T017 entry, eliminating the internal §7 contradiction (Constitution
  V). Same fix-incomplete-within-coupling shape as M10 + MAJ-2; one
  section earlier in the same file.
- **M12 — §15 #1 "Open Questions" entry closing sentence (redteam r2
  MAJ-3):** the §15 #1 entry closed with "SECURITY-DECISIONS.md
  rationale entries still owed for both once that file is authored" —
  doubly verifiably false (the Tor entry IS authored under T017 at
  SECURITY-DECISIONS.md §"2026-07-04 — Tor sidecar trust rationale
  (FR-015)"; the file exists at repo root; the Constitution v1.1.0
  Sync Impact Report no longer lists it as TODO). The r1 review's
  sibling-paragraph hunt scanned §7 + §16.1 but missed §15. T018
  rewrites the closing sentence to honestly describe the Tor entry as
  authored (T017) and only Nym as outstanding. The T017a r1→r2→r3
  pattern held for one more round; the redteam's whole-file grep
  predicts MAJ-3 is the last sibling carrying the stale-existence
  pattern.

### Gated (no standing human vigilance needed; green verify.sh is the proof)

- M1 UID/GID cross-equality between spec and compose: gated by the
  contract tests on compose UID/user directives (T015's
  `tests/contract/compose/`, T022's transport invariants at runtime).
  Spec prose alone is not gated; the runtime tests catch compose drift.
- M3 audit_log enum vs. data-model.md §4: spec-vs-data-model drift is not
  currently gated by a contract test; T018's verification is at `/start`
  only (manual read of both sections). The SQL migration that lands under
  T012 is the authoritative enum at runtime; this M3 is paperwork-class.
- M4 Tor-row digest pin: gated at the digest-source layer by T015's
  compose contract test + T017's `tor_entry_test.sh` cross-equality
  check. Spec prose referencing FR-015 is not gated by a contract test.
- M5 SOCKS5 reply column: gated at the byte-emission layer by T028
  (`AUTH_REQUIRED` byte-exact), T019a + T067 (`ROUTE_DOWN` / `DISABLED`
  byte-exact). Spec prose matching the contract doc is not gated.
- M9 / M10 §16.1 lock-step with SECURITY-DECISIONS.md docker-socket-proxy
  entry: M10's positive assertion is currently gated entry-block-scoped
  (T017a's contract test on SECURITY-DECISIONS.md). **T018 ADDS a new
  arch-spec contract test** (`tests/contract/arch/docker_socket_proxy_
  section_test.sh`) that scopes the same assertions to spec.md §16.1, so
  the lock-step is gated on BOTH sides going forward. This is the
  follow-up T017a's R8 mentioned as "could be authored in T018 if the
  implementer wants to gate the lock-step going forward" — gated.

### Residue (what no gate catches — redteam + reviewer focus here)

- **R1 — M2 §5.5 snapshot-description prose.** No contract test asserts
  that spec.md §5.5's snapshot description omits the route mask. A future
  re-introduction would slip past verify.sh. Mitigation: T018's new arch
  contract test could be extended to assert §5.5 lacks "+ route" prose,
  but that risks false-positives on incidental mentions; left as
  reviewer-enforced coupling for now (filed as a follow-up note in
  §Out-of-scope).
- **R2 — M3 audit_log enum drift between spec and data-model.** Not
  gated. A future feature adding an action could update one and not the
  other. Mitigation: a contract test asserting the rendered enum in
  spec.md §6.5 ⊆ data-model.md §4 would close this, but the canonical
  enum is the SQL migration (data-plane + control-plane runtime tests
  catch the actual schema); spec-vs-data-model drift is paperwork-class.
  Filed in §Out-of-scope.
- **R3 — M4 Tor-row prose referencing FR-015.** No contract test asserts
  the spec.md §7 Tor row points at FR-015 (or names the apt-key
  fingerprint file, etc.). A future softening could narrow this. The
  actual pin values are gated at the artifact layer (digest / fingerprint
  files + contract tests). Residual is paperwork-class.
- **R4 — M5 SOCKS5 reply column.** Same shape as R3 — prose-vs-contract-
  doc drift is not gated, byte emission is gated at the impl layer.
- **R5 — M6 §10.3 "three" vs "four" wording.** A contract test on
  spec.md §10.3 asserting "three" might be defensible (low false-
  positive risk — the word is bounded). Filed as a possible follow-up in
  §Out-of-scope; not promoted into the gated set in this ticket to keep
  scope tight to the eight amendments T018 explicitly owns.
- **R6 — M7 §14.4 NEEDS CLARIFICATION absence.** Not gated. A future
  re-introduction of the marker (e.g., a feature speculating about
  WebExtensions keyring support) would slip past. Thecanonical storage
  path is gated by the data-model.md §5.1 byte-equality test (T056);
  spec-vs-data-model prose drift is paperwork-class.
- **R7 — M8 §15 #6 resolution flag.** Not gated. The maintenance flag
  "re-verify on each Mullvad Browser major-version bump" lives in prose
  only — no test enforces the cadence. Operator discipline.
- **R8 — §16.1 cross-artifact coupling, completeness of M9+M10 fix.**
  Even with the new arch contract test gating the load-bearing clauses
  (root-run acknowledgement, three-reacher release-blocker), a future
  drift on a clause the test does NOT assert would slip past. Mitigation:
  the test's positive assertions are scoped to the two specific clauses
  T017a r3 flagged; the rest of §16.1 is reviewer-enforced coupling
  (Constitution V). Documented; not a follow-up ticket unless the user
  wants a full §16.1 ↔ SECURITY-DECISIONS.md prose-diff test (out of
  scope here — that would be a §16.1-full-block diff, much larger than
  the two-clause gate T018 ships).

## Acceptance

T018 is a documentation-only amendment. The contract is captured by ONE
new arch-spec contract test (hermetic structural + cross-file) PLUS the
existing SECURITY-DECISIONS.md entry-block test remaining green. No new
runtime code ships.

### Named tests

1. **NEW: `tests/contract/arch/docker_socket_proxy_section_test.sh`**
   (hermetic; grep + awk only; no network, no daemon). Scopes assertions
   to spec.md §16.1 (extracted by anchor `### 16.1 \`docker-socket-proxy\``
   through the next `^---` separator). Asserts the two §16.1 drift fixes:
   - **A-M9 (root-run honesty)**: §16.1 MUST carry the "runs as root" /
     "no defense-in-depth user-isolation control" framing; §16.1 MUST
     NOT contain the false "unprivileged user its upstream image
     declares" clause.
   - **A-M10 (three-reacher release-blocker)**: the §16.1 release-blocker
     paragraph (extracted by anchor `**Profile applicability**` through
     next blank line) MUST name the data plane (`(data plane|\bDP\b)`)
     AND Tor (`\bTor\b`); §16.1 MUST NOT contain the CP-only narrowing
     phrase "expose the CP to non-localhost" as the sole reacher.
   - **A-cross (cross-artifact digest + T017a entry existence)**: the
     tecnativa digest from `compose/env/local.env.example`'s
     `DOCKER_SOCKET_PROXY_IMAGE=` line MUST appear in spec.md §16.1
     (verbatim cross-equality, same shape as T017a's M5 on the entry
     side) — gates silent digest bumps at either file.

2. **EXISTING: `tests/contract/security-decisions/docker_socket_proxy_entry_test.sh`**
   (T017a) MUST remain GREEN — T018 does not touch SECURITY-DECISIONS.md.

3. **EXISTING: `tests/contract/security-decisions/tor_entry_test.sh`**
   (T017) MUST remain GREEN — T018 does not touch the Tor entry.

### Behavioral assertions (PR-time verification at `/start`; the contract
test above gates regression going forward)

- §4.3: `compose/docker-compose.local.yml` lines `user: "5101:5100"` (CP)
  and `user: "5102:5100"` (DP); `local.env.example` documents the same
  triple. NO edit required at §4.3.
- §5.5 line ~316-318: phrase "+ route enable/disable mask" struck;
  replaced with a cross-reference to `data-model.md §1.4 / §2`.
- §6.5 line ~391: spurious `sidecar_restart` entry removed from enum
  comment; rendered enum now matches data-model.md §4 exactly. Every
  action this feature inserts (`config_error`, `sidecar_healthy`,
  `sidecar_unhealthy` — three, not four; T074 makes RESTARTED event-only)
  is listed. V001__init.sql line 67 carries the same spurious entry;
  filed as follow-up (out of T018 scope — T012 owns the SQL migration).
- §7 Tor row line ~415: `NEEDS CLARIFICATION` marker dropped; replaced
  with a FR-015 reference naming the Stargate-built image, the digest
  pins (base + final), and the apt-key fingerprint verification at
  build time, with the SECURITY-DECISIONS.md rationale cited.
- §10.1 lines 564-571: SOCKS5 reply column matches
  `contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"`.
  NO edit required unless drift found.
- §10.3 step 2 line ~604: "four" → "three".
- §14.4 lines 871-874: `NEEDS CLARIFICATION` marker stripped; cross-ref
  to FR-019 + research.md §6 + data-model.md §5.1 added.
- §15 #6 lines 941-943: marked resolved-for-v1 with maintenance entry
  noting re-verify on each Mullvad Browser major-version bump.
- §16.1 line ~994: "unprivileged user its upstream image declares"
  clause deleted; "no defense-in-depth user-isolation control; proxy
  runs as root" framing added.
- §16.1 line ~998-1004: CP-only release-blocker sentence widened to
  CP/DP/Tor.

### Runnable command

```
scripts/verify.sh
```

Expected after T018 lands: PASS count increments by 1 (the new arch
contract test); existing tests remain green. Range: PASS=8 SKIP=2 FAIL=0.

## Out-of-scope

- **Do NOT touch `SECURITY-DECISIONS.md`.** The docker-socket-proxy entry
  is closed (T017a). T018 lands the §16.1 reconciliation from the arch-
  spec side; T017a's drift-reconciliation paragraph in the entry stands
  as the historical record (per the append-only discipline; a future
  superseding dated entry would land in its own ticket if needed).
- **Do NOT amend THREAT-MODEL.md.** T082 owns the THREAT-MODEL §8.6 + §2.6
  fixes. The THREAT-MODEL §3.1 citation in T017a's entry stays as-is.
- **Do NOT author a full §16.1 ↔ SECURITY-DECISIONS.md prose-diff test.**
  T018 ships the two-clause gate (root-run + three-reacher release-
  blocker) scoped to §16.1. A full prose-diff would be much larger than
  the two specific clauses T017a r3 flagged; left as a follow-up note.
- **Do NOT add §5.5 / §6.5 / §7 / §10.1 / §10.3 / §14.4 / §15 contract
  tests** in T018. The amendments at those sections are paperwork-class
  prose updates with their canonical values gated at the artifact layer
  (compose, SQL migration, byte-emission tests). Adding spec-prose
  contract tests for each would balloon T018's scope; the residue items
  R1, R2, R3, R4, R5, R6, R7 document the unfalsified surface for
  redteam focus.
- **Do NOT bump the docker-socket-proxy image digest.** The digest pin
  is the canonical source-of-truth at `compose/env/local.env.example`;
  T018 only verifies the digest appears in §16.1 verbatim.
- **§16.1 itself, paragraphs OTHER than the two flagged ones:** touch
  only if a sibling paragraph carries the same false claim shape (the
  T017a don't-rediscover lesson — scan sibling paragraphs when fixing a
  redteam-flagged clause). If no sibling carries the defect, leave the
  rest of §16.1 untouched.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
