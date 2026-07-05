---
id: T017a
title: 'Append to `SECURITY-DECISIONS.md` (created by T017) the **`docker-sock'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T017a
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 4
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-015
  - specs/000-architecture/spec.md#16.1
  - THREAT-MODEL.md#3.1
decision_refs:
  - SECURITY-DECISIONS.md
  - compose/docker-compose.local.yml
  - compose/env/local.env.example
reviews: { round: 1, date: 2026-07-04, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T017a: Append to `SECURITY-DECISIONS.md` (created by T017) the **`docker-sock

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Append to `SECURITY-DECISIONS.md` (created by T017) the **`docker-socket-proxy` aux container** trust rationale (T015 / T039): why a privilege-isolating proxy instead of mounting `/var/run/docker.sock` directly into the CP. State the property the proxy buys: a compromise of the Quarkus control plane (YAML parser, gRPC server, future admin UI) does NOT escalate to host root, because the CP holds no docker.sock handle and can only invoke the `EVENTS=1 CONTAINERS=1` GET-only surface the proxy exposes. State the residual trust honestly: the proxy itself IS in the TCB; a compromise of the proxy is host-root-equivalent. Mitigations recorded: digest-pinned image (Principle IV); `POST=0` lockdown gated by T019c contract test; proxy runs as the unprivileged user its upstream image declares; proxy is not reachable from outside the compose-internal network. Cross-reference THREAT-MODEL.md §3.1 (local profile assumes local code execution is already game-over) so the residual-risk framing is consistent. **Release-blocker on any future LAN or VPS profile feature spec**: that profile exposes the CP to non-localhost callers and changes the compromise-probability calculus; this entry MUST be revisited (and likely the proxy mechanism replaced) before the LAN/VPS spec ships.

## Analysis

Property map (per `docs/process/analysis.md`), grounded against FR-015,
`SECURITY-DECISIONS.md` (the file T017 created + the append-only preamble
that now binds every future edit), `compose/docker-compose.local.yml`
(the docker-socket-proxy service definition + the `:ro` mount honesty
comment), `compose/env/local.env.example` (the digest source-of-truth),
arch §16.1 (the auxiliary-container section that ALREADY points back here:
"Mitigations recorded in `SECURITY-DECISIONS.md` (entry created by
T017a)"), THREAT-MODEL §3.1 (the local-profile residual-risk framing),
and the existing `tests/contract/security-decisions/tor_entry_test.sh`
whose M8 (`lacks "docker-socket-proxy"`) this ticket MUST relax.

### Must hold

- **M1 — Append, don't create.** `SECURITY-DECISIONS.md` already exists
  (T017). T017a APPENDS a new dated entry at the TOP of the
  dated-decisions region (newest-first per the preamble T017 locked in),
  directly below the preamble's `---` separator and above the existing
  `## 2026-07-04 — Tor sidecar trust rationale` entry. No edit to the
  preamble or to the Tor entry's body (Constitution VI — entry-body
  immutability; only a superseding entry may rewrite a body, and this
  ticket does not supersede the Tor entry).
- **M2 — Property bought (the load-bearing claim).** The entry states
  WHY a privilege-isolating proxy instead of mounting
  `/var/run/docker.sock` directly into the CP, in property form: a
  compromise of the Quarkus control plane (YAML parser, gRPC server,
  future admin UI) does NOT escalate to host root, because the CP holds
  no `docker.sock` handle and can only invoke the `EVENTS=1 CONTAINERS=1`
  GET-only surface the proxy exposes. This is the property arch §16.1
  already cites ("Mitigations recorded in `SECURITY-DECISIONS.md` (entry
  created by `specs/001-tor-route/` T017a)"); T017a delivers it.
- **M3 — Residual trust honest (Principle V).** The entry states plainly
  that the proxy itself IS in the TCB; a compromise of the proxy is
  host-root-equivalent (it holds the docker.sock handle and can issue any
  Engine API call the daemon serves — the `:ro` mount is convention-only
  on AF_UNIX sockets, NOT a kernel-enforced boundary; the
  `docker-compose.local.yml` comment block already says so). Naming this
  honestly is the whole point of the entry.
- **M4 — Mitigations recorded (matches the task body's enumerated list
  verbatim).** The entry records: (a) digest-pinned image (Principle IV);
  (b) `POST=0` + `EVENTS=1` + `CONTAINERS=1` lockdown gated at runtime by
  T019c contract test (parallel ticket, not yet landed); (c) proxy runs
  as the unprivileged user its upstream image declares; (d) proxy is not
  reachable from outside the compose-internal network (no `ports:` key in
  the service definition).
- **M5 — docker-socket-proxy image digest recorded AND cross-equals the
  env.example source-of-truth.** The entry quotes
  `tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2`
  verbatim from `compose/env/local.env.example` (single source of truth;
  `compose/docker-compose.local.yml` reads it via `${DOCKER_SOCKET_PROXY_IMAGE}`).
  The contract test (AT-1) cross-checks the two locations to promote
  drift-detection into the PR-cadence gate — exactly the pattern T017
  used for the Tor apt-key fingerprint + base digest.
- **M6 — THREAT-MODEL §3.1 cross-reference.** The residual-risk framing
  cites §3.1 so the "proxy compromise is host-root-equivalent" prose
  anchors to §3.1's "an attacker who gains local code execution can
  replace the data-plane binary on disk, swap a sidecar image, or read
  the inter-plane keys" — i.e. local profile already assumes local code
  execution is game-over, so the proxy-compromise residual is consistent
  with the mode's threat model rather than a new assumption.
- **M7 — arch §16.1 cross-reference.** The entry cites §16.1 so the
  spec↔decision-log round-trip is closed (§16.1 points at T017a; T017a
  points back at §16.1). Without this, an auditor reading the arch spec
  sees the pointer but the entry has no back-link.
- **M8 — LAN/VPS release-blocker flag.** The entry flags — in prose,
  directly under the residual-trust paragraph — that any future LAN or
  VPS profile feature spec exposes the CP to non-localhost callers and
  changes the compromise-probability calculus; the proxy mechanism MUST
  be revisited (and likely replaced) before the LAN/VPS spec ships. This
  is the literal text of the task body's "Release-blocker on any future
  LAN or VPS profile feature spec" sentence and is the most operationally
  load-bearing forward-looking claim in the entry.
- **M9 — Scope boundary: T017's M8 contract assertion MUST be relaxed.**
  T017's `tests/contract/security-decisions/tor_entry_test.sh` currently
  asserts `lacks "docker-socket-proxy"` (the T017 scope boundary). T017a
  APPENDS that rationale, so the assertion MUST be removed in this same
  ticket's diff; leaving it would fail the gate the moment the docker
  entry lands. Authorized by §Out-of-scope (the test edit is the ticket's
  whole point, not a drive-by).

### Gated (verify.sh catches fail-closed)

- **G1 — New structural + cross-file contract test**
  `tests/contract/security-decisions/docker_socket_proxy_entry_test.sh`
  (verify gate 4, auto-discovered via `find tests/contract -name
  '*_test.sh'`) → M1 (new dated entry heading present, above the Tor
  entry), M2 (property-bought keywords — "host root", "CP", "compromise",
  "does NOT escalate"; **plus** DP/Tor exposure named — redteam r1
  MAJOR-2 promotion), M3 (residual-trust keywords — "TCB",
  "host-root-equivalent", **plus** "code-exec inside the proxy container"
  framing AND transitive-dep closure / HAProxy / base-image / libssl3-
  analogue named outside the env-flag filter — redteam r1 MAJOR-1
  promotion), M4 (mitigation keywords — `POST=0` / `EVENTS=1` /
  `CONTAINERS=1` / T019c / digest-pinned / compose-internal, **plus**
  the verified-empty `Config.User` clause — redteam r2 MAJOR-2 promotion),
  M5 (digest present AND cross-equals
  `compose/env/local.env.example`'s `DOCKER_SOCKET_PROXY_IMAGE` value),
  M6 (`§3.1` citation present), M7 (`§16.1` citation present), M8
  (LAN/VPS release-blocker keywords present), M9 (regression guard —
  forbids the "limited to CP-process-compromise" narrowing that redteam
  r2 MAJ-1 caught as a fix-incomplete defect in the Release-blocker
  paragraph). The M5 cross-file check promotes drift-detection into the
  gate. **All keyword assertions are line-range-scoped to the
  docker-socket-proxy entry block (DSP_LINE..TOR_LINE-1) — redteam r2
  MIN-1 promotion** so the sibling Tor entry's `libssl3` / `Tor` tokens
  stop satisfying the r1-promoted clauses (without this scoping the
  promotion is non-load-bearing). The redteam r1+r2 promotions make the
  rationale-prose honesty invariants PR-cadence-gated: a future
  softening that strips any of them fails the test.
- **G2 — T017's tor_entry_test.sh M8 relaxation.** The M8 block
  (`lacks "docker-socket-proxy"`) is removed; the test file's header
  comment block is updated to record that T017a landed the docker-socket-proxy
  entry and the scope-boundary signal is obsolete. All other M-numbers
  in tor_entry_test.sh (M1–M7, M9, M10) keep passing unchanged: the new
  entry's content does not contain a Tor-fingerprint match, a base-digest
  match, an `8.6` §8.6 citation, a `libssl3` reference, or a fabricated
  final-image digest.

### Residue (no gate catches — redteam focus)

- **R1 — Rationale prose correctness.** The "property bought" and
  "residual trust" prose is prose; G1 asserts keyword presence, not
  that the argument is sound or complete. **Downstream gate:** review +
  redteam (this ticket is `privacy_critical: true` → redteam fires). The
  redteam is the correctness gate for the trust argument itself, exactly
  as it was for T017 (where it fired 3 MAJORs over 3 rounds). **(Materialized
  at redteam round 1: 3 MAJORs — all Constitution V honesty defects on
  the residual framing. MAJOR-1: residual was scoped to "env-flag-filter
  bypass" only, omitting the proxy's HAProxy-frontend / base-image /
  transitive-dep closure as TCB outside the filter (same libssl3-analogue
  shape T017 hit). MAJOR-2: property-bought was scoped to CP-only but
  the proxy is reachable by the DP (the untrusted-bytes boundary) and
  Tor too. MAJOR-3: the "unprivileged user" mitigation misled — the
  proxy's non-root UID contributes nothing because the docker.sock
  handle is the pivot and Docker runs as root. All three fixed in-ticket
  + promoted into G1's contract-test assertions so a future softening
  fails the gate. Path (b) of the original residual enumeration was
  fictional and removed.)** **(Materialized at redteam round 2: 2 MAJORs
  — both fix-introduced / fix-incomplete defects of the exact T017-r2
  shape. MAJ-1: the r1 MAJOR-2 widening landed in the Exposure-surface
  paragraph but was NOT propagated to the Release-blocker paragraph,
  which still narrowed the local-profile exposure surface to
  "CP-process-compromise" — the entry internally contradicted itself.
  Fixed: Release-blocker paragraph rewritten to align with
  Exposure-surface, + M9 regression guard forbids the narrowing pattern.
  MAJ-2: the r1 MAJOR-3 demoted unprivileged-user sub-note rested on
  "the tecnativa image declares a non-root user today" — verified FALSE
  via `docker image inspect` (Config.User empty = root); deleted the
  sub-note, replaced with the honest verified-empty clause. Plus 2 MINORs
  fixed: M2/M3/M4 contract-test assertions line-range-scoped to the
  entry block so the Tor entry's tokens stop satisfying them (MIN-1);
  AT-4 stale R-numbering updated to R1–R8 with R5 rewritten (MIN-2).)**
  Round 2 was the round that caught fix-introduced defects; round 3
  caught the cross-artifact coupling defect (entry asserted §16.1 lock-
  step; §16.1 had drifted on the same two r2-struck points). The r3
  fix retracts the lock-step claim to honesty and references T018 as
  the natural owner of the §16.1 reconciliation.
- **R2 — T019c dependency.** M4(b) claims "`POST=0` lockdown gated by
  T019c contract test" — T019c is a parallel Phase-2 ticket that has not
  landed yet. Until it does, the lockdown is asserted only by
  `docker-compose.local.yml`'s env-block; if T019c is dropped or
  modified, this entry's claim drifts. **Downstream gate:** T019c.
  (Redteam r1 MINOR-1: property-bought paragraph now carries the T019c
  hedge too, not only the mitigation paragraph; previously a reader of
  property-bought alone got a stronger claim than the entry delivered.)
- **R3 — Digest liveness.** G1's M5 cross-file check proves
  SECURITY-DECISIONS.md matches `compose/env/local.env.example`, NOT
  that the digest is currently served by Docker Hub (the tecnativa
  maintainers could re-tag `0.3.0` at a different sha256, though this is
  industry-discouraged). **Downstream gate:** `scripts/ground-check.sh`
  ONLINE mode resolves compose `image:` references against the registry
  and FAILs on a pruned/malformed digest — at release cadence, not PR
  cadence (T081 makes it release-mandatory). The
  `compose/env/local.env.example` comment block already documents this
  gate; this entry inherits it without re-stating.
- **R4 — Proxy-filter correctness assumption.** M2's property-bought
  claim ("the CP/DP/Tor can only invoke the GET-only surface the proxy
  exposes") is true ONLY IF `tecnativa/docker-socket-proxy` correctly
  enforces its env-flag filter AND its HAProxy frontend + entrypoint +
  base closure are behaviourally conforming (redteam r1 MAJOR-1
  promotion — the residual was widened from "filter bypass" to "any
  code-exec inside the proxy container"). A bug in the upstream proxy
  that silently leaks a non-allowlisted endpoint would void the property
  without any Stargate-side symptom. **Downstream gate:** T019c (runtime
  lockdown test, when it lands). No PR-cadence Stargate-side gate
  catches it; the digest pin means the behaviour is pinned as long as
  the digest is pinned, so R4 folds into R3 once T019c lands.
- **R5 — Image's `Config.User` is empty (proxy runs as root); no
  defense-in-depth user-isolation control exists.** Redteam r2 MAJOR-2
  verified via `docker image inspect
  tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2
  --format '{{.Config.User}}'` at T017a commit time → empty = root. The
  prior draft's "declares a non-root user today" claim was FALSE (same
  shape as T017 r2 libssl3 — an unverified upstream-artifact claim
  asserted as fact); the entire unprivileged-user sub-note was deleted
  and replaced with an honest "no defense-in-depth user-isolation
  control" clause naming the verified-empty `Config.User`. A future
  tecnativa major-version bump could add a `USER` directive; the bump
  procedure (in the entry) re-runs `docker image inspect` and supersedes
  the clause if so. **Downstream gate:** review at digest-bump time +
  the in-entry `docker image inspect` mandate.
- **R6 — LAN/VPS release-blocker is prose, not enforced.** M8's
  release-blocker flag is prose; no contract test enforces "if a LAN or
  VPS compose file appears in the repo, its SECURITY-DECISIONS.md entry
  must supersede this one." That is a forward-looking concern for the
  future LAN/VPS feature spec, not something this ticket can gate.
  **Downstream gate:** review at LAN/VPS spec time; the M8 prose +
  §16.1's own release-blocker sentence carry the norm. A concrete
  enforceable gate is cheap (a contract test that fails on
  `compose/docker-compose.lan.yml` or `compose/docker-compose.vps.yml`
  appearing in the repo without a superseding entry) — filed as a
  follow-up for the LAN/VPS spec, not for T017a.
- **R7 — Operator-override of `DOCKER_SOCKET_PROXY_IMAGE` bypasses the
  M5 cross-file invariant (redteam r1 MINOR-4).** Compose reads
  `${DOCKER_SOCKET_PROXY_IMAGE}` from whatever `--env-file` the operator
  passes; `scripts/stargate init` (T016) and the BYO-env path both
  write/let-the-operator-edit a gitignored `compose/env/local.env`. The
  M5 cross-file check reads only `local.env.example`. An operator who
  overrides the digest in `local.env` runs a different image than this
  entry records, with no contract test catching the override. The entry
  now carries an explicit operator-override caveat + the "MUST re-record
  any override as a superseding entry" norm. **Downstream gate:**
  operator discipline + review at any operator-reported incident.
- **R8 — §16.1 has drifted from this entry on two points AS OF T017a
  COMMIT TIME (redteam r2 MINOR-2 → r3 MAJOR-1 promotion).** §16.1's
  mitigation list still names "proxy runs as the unprivileged user its
  upstream image declares" (verified FALSE at r2 — `Config.User` is
  empty, proxy runs as root) AND §16.1's release-blocker sentence is
  CP-only (r2 MAJ-1 caught the same narrowing in this entry's own
  Release-blocker paragraph; this entry was widened, §16.1 was not).
  The entry's prior draft asserted "kept in lock-step" — false at commit
  time. **Fixed at r3:** the entry now honestly names the drift,
  declares itself the authoritative resolution, and references T018
  (whose mandate already includes "verify at implementation time that…
  T017a's `SECURITY-DECISIONS.md` entry remains the authoritative
  rationale") as the natural owner of the §16.1 reconciliation — same
  shape as the THREAT-MODEL §8.6 gap T017 left for T082. The contract
  test's M9 regression guard is paragraph-scoped to the Release-blocker
  paragraph with a positive DP/Tor-presence assertion (inverted-shape
  per the redteam's r3 recommendation — regex tripwires cannot
  distinguish "the entry narrows" from "the entry honestly describes
  §16.1's narrowing"). **Downstream gate:** T018 (arch-spec amendment).

## Acceptance

- **AT-1 (tests-first, Principle VII).** Add
  `tests/contract/security-decisions/docker_socket_proxy_entry_test.sh`
  (structural + cross-file contract test; hermetic — no network, no
  daemon, just file reads + grep + diff against artifact files). It MUST
  pass under verify gate 4 and assert, at minimum:
  - **M1 (new dated entry above the Tor entry):** SECURITY-DECISIONS.md
    contains a `## 2026-07-04 — docker-socket-proxy trust rationale`
    heading AND it appears BEFORE the `## 2026-07-04 — Tor sidecar trust
    rationale` heading (newest-first ordering; reverse-chronological
    violates the preamble's "newest first" rule).
  - **M2 (property bought):** the entry contains keywords for the
    load-bearing property — `docker.sock` AND `host root` AND a phrase
    asserting the CP-compromise-does-not-escalate property (e.g.
    "does not escalate", "cannot escalate", "does NOT escalate", or
    "not.*host root").
  - **M3 (residual trust honest):** the entry contains keywords for the
    TCB / host-root-equivalent residual — `TCB` AND a phrase asserting
    proxy-compromise-is-host-root-equivalent (e.g. "host-root-equivalent",
    "host root equivalent", or "compromise of the proxy").
  - **M4 (mitigations recorded):** the entry references ALL of
    `POST=0`, `EVENTS=1`, `CONTAINERS=1`, T019c, AND a digest-pinning
    keyword (e.g. "digest-pinned", "digest pin", or `@sha256:`), AND a
    compose-internal / non-routable keyword (e.g. "compose-internal",
    "no `ports:`", "not reachable").
  - **M5 (digest + cross-file):** the docker-socket-proxy digest
    `sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2`
    appears in SECURITY-DECISIONS.md AND equals the digest in the
    `DOCKER_SOCKET_PROXY_IMAGE=` line of
    `compose/env/local.env.example`. Drift fails the test.
  - **M6 (THREAT-MODEL §3.1 citation):** the entry contains `§3.1` or
    `3.1` AND a THREAT-MODEL keyword (e.g. "THREAT-MODEL", "threat
    model", "local profile").
  - **M7 (arch §16.1 citation):** the entry contains `§16.1` or `16.1`
    AND an arch-spec keyword (e.g. "arch", "architecture spec", "§16",
    "auxiliary").
  - **M8 (LAN/VPS release-blocker):** the entry contains
    LAN-or-VPS-flavoured release-blocker keywords (e.g. "LAN", "VPS",
    "release-block", "MUST be revisited", "non-localhost").
- **AT-2 (T017 M8 relaxation, in scope per §Out-of-scope).** Remove the
  M8 `lacks "docker-socket-proxy"` block from
  `tests/contract/security-decisions/tor_entry_test.sh` (lines
  approximately 139–143 + the surrounding comment block) and replace
  with a 1-line comment recording that T017a landed the docker-socket-proxy
  rationale and the scope-boundary signal is obsolete. All other M-numbers
  in `tor_entry_test.sh` (M1–M7, M9, M10) continue to pass unchanged
  (the new entry's content does not trip them).
- **AT-3.** `scripts/verify.sh` is GREEN (the new contract test passes;
  the relaxed tor_entry_test.sh passes; no existing gate regresses).
  Expected post-merge count: PASS=7 SKIP=2 FAIL=0 (was PASS=6 at HEAD).
- **AT-4 (residue acknowledgement, non-blocking).** §Analysis R1–R8 each
  map to a named downstream gate (redteam for R1, T019c for R2, release
  ground-check for R3, T019c for R4, R5 closes at digest-bump review
  liveness + the now-required declared-user inspect — distinct from R3,
  operator discipline for R7, review at proxy-mechanism-change for R8,
  future-spec review for R6).

## Out-of-scope

- **The docker-socket-proxy runtime lockdown contract test (T019c)** —
  parallel Phase-2 ticket. T017a CITES it (M4(b), R2); it does not
  author it.
- **Any edit to THREAT-MODEL.md or arch spec.md.** §3.1 and §16.1 are
  already written; T017a cites them, it does not edit them. (T082 owns
  the THREAT-MODEL §8.6 amendment; T018 owns arch §7; neither is this
  ticket.)
- **Any edit to the Tor entry's body.** Constitution VI: the entry body
  is immutable once committed. T017a only adds a sibling entry above it
  + the Tor entry's `§8.6 Resolves` cross-link and the SECURITY-DECISIONS.md
  final-image-digest gap reference both remain verbatim.
- **Any edit to the SECURITY-DECISIONS.md preamble.** T017 locked the
  append-only convention + the immutability clause; T017a appends per
  the convention, it does not modify the rules.
- **A new Tor-side cross-file assertion for the docker-socket-proxy
  digest in `tor_entry_test.sh`.** The Tor entry's contract test
  belongs to T017; T017a owns its own contract test file
  (`docker_socket_proxy_entry_test.sh`) for the new entry's positive
  assertions. The ONLY edit to `tor_entry_test.sh` is the M8 relaxation
  (AT-2) — that edit is the ticket's whole point, not a drive-by.
- **Renaming `tor_entry_test.sh`** to a more general
  `security_decisions_test.sh`. The file is the Tor entry's contract
  test (named after T017's deliverable); future entries get their own
  files mirroring the pattern. Renaming would expand scope into T017's
  surface.
- **Editing `scripts/check-license-headers.sh` to scan `.md` files.**
  Same boundary as T017 — the SPDX header on SECURITY-DECISIONS.md is
  asserted by the contract test (T017 AT-1 M1 + now T017a's
  docker_socket_proxy_entry_test.sh inherits).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
