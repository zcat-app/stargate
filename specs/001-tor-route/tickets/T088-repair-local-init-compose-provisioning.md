---
id: T088
title: 'Repair local init and Compose provisioning'
status: done
created: 2026-07-11
last_updated: 2026-07-17
source: review/sol-review.md#B1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T087, T092, T094, T095, T099]
parallel: false
files_budget: 20
privacy_critical: true
constitution_refs:
  - "II: Plane separation"
  - "III: Privacy-preserving by construction"
  - "VII: Tests-first for privacy-critical and contract code"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/000-architecture/spec.md §9
  - specs/001-tor-route/spec.md §SC-001
  - specs/001-tor-route/data-model.md §6
decision_refs: []
remediates: T016
reviews: { round: 1, date: 2026-07-17, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T088: Repair local init and Compose provisioning

## Context

The shipped `init` path cannot create the local stack: it omits the env file,
uses logical volume names as physical names, guesses container names, and does
not initialize writable mounts for the non-root service UIDs. This remediates
T015/T016 and is a release blocker for SC-001.

## Analysis

- **Must hold (Constitution II — plane separation):** the fixed `init`
  introduces no CP→DP startup coupling. It provisions volumes + keys +
  pepper and brings the stack up, but the data plane still boots and
  routes with no CP dependency — compose's existing DP `no-depends_on`
  (compose/docker-compose.local.yml:51-54) is untouched. Volume/key
  provisioning is install-time only, never a request-path participant.
- **Must hold (Constitution III — no outbound except a routed request):**
  `init` opens no outbound socket except the Docker daemon socket and the
  image pulls the daemon performs. No curl/wget, no telemetry. The pepper
  is generated locally (`openssl rand -bytes 32`); nothing leaves the
  host. (The T016 init_test.sh M12 no-curl/wget literal gate is
  preserved.)
- **Must hold (Principle VII — tests-first, no AI exception):** the
  Docker-backed regression test exists and FAILS against the pre-fix
  installer for the B1 reasons (logical-vs-physical volume names, guessed
  container names, uninitialized writable mounts) BEFORE the fix lands,
  then passes after. The ticket §Notes fail-then-pass requirement is the
  load-bearing falsification step.
- **Must hold (B1 / acceptance #2):** one compose-command builder is
  authoritative for project name, compose file, and env file; `init` and
  every quickstart invocation use it, so project-scoped identity is
  consistent everywhere it appears.
- **Must hold (B1 / acceptance #3):** volume initialization resolves
  project-scoped physical names by Compose labels/rendered config; no
  literal `stargate-*` physical name is assumed by the installer.
- **Must hold (acceptance #4):** the key volume is fail-closed —
  existing keys are preserved (4/4 → skip regen), a partial 1–3 of 4
  keyset aborts (exit 20), and permissions match the inter-plane
  contract (cp.priv/dp.priv 0600, cp.pub/dp.pub 0644, group stargate-ipc
  GID 5100). The M5 do-not-clobber guard and the M4 UID/GID cross-file
  literals are preserved.
- **Must hold (T092 amendment / acceptance #4):** `init` provisions
  `/etc/stargate/keys/pepper.key` — 32 bytes from `openssl rand -bytes
  32`, mode 0640, owner `stargate-cp` (UID 5101, the natural
  provisioner/writer), group `stargate-ipc` (GID 5100) so BOTH planes
  read it via their shared supplementary GID (CP mounts the keys volume
  rw, DP :ro). Co-located with the ed25519 keypairs in `stargate-keys`.
  Fail-closed: an existing pepper is preserved (never regenerated short
  of explicit operator rotation); a partial keyset still aborts.
- **Must hold (B1 / acceptance):** health discovery uses
  `docker compose -p <project> ps -q <service>`, never guessed container
  names; the timeout path still leaves containers up (arch §9.2, M7
  no-`compose down` gate preserved).
- **Gated:**
  - `tests/contract/stargate-cli/init_docker_test.sh` (NEW, this ticket)
    is the fail-then-pass regression test. It sources the
    compose-command builder (extracted into `scripts/lib/compose.sh`) for
    hermetic command-render + physical-name-resolution assertions, and
    uses a tiny-fixture compose stack (no Stargate build) under TWO
    isolated project names to prove env loading, project isolation,
    volume ownership/mode incl. pepper, idempotent rerun, and health
    lookup — exactly B1's recommendation. It self-SKIPs (exit 0 with a
    SKIP notice) when the Docker daemon is unreachable, so `verify.sh`
    stays green on Docker-less hosts and runs the real assertions where
    Docker is present.
  - `tests/contract/stargate-cli/init_test.sh` (T016, hermetic) keeps
    gating the script-level invariants (exit codes 10/20/30/40/50,
    UID/GID literals 5101/5102/5100, key filenames, no `compose down`,
    Tor-only verify, keygen-image digest pin + cross-file equality with
    sidecars/tor/Dockerfile, `*@sha256:*)` override guard) — updated in
    lockstep where this ticket changes init's contract surface.
  - `scripts/lint-ticket.py` + license-header gate cover mechanical shape.
- **Residue:**
  - Docker-daemon and host-platform variance (storage driver, rootless
    mode, Compose plugin version skew) is release-cadence coverage owned
    by T077's quickstart walkthrough on a reference workstation; the
    PR-cadence fixture test asserts the contract against THIS daemon only.
  - The pepper is provisioned but not yet READ (CP `TokenLoader` / DP
    `auth` land with T035a/T044); the residue is "the file exists with
    the right shape" — the read-side contract is those tickets' burden.
  - No static check forbids a future regression to literal `stargate-*`
    physical volume names; the fixture test's two-project isolation case
    is the guard, but a compose edit could re-couple. Redteam scope.

### Grounding decisions (2026-07-17 /run T088)

- **acceptance #5 scope — export/import/wipe are NOT implemented here.**
  Grounding against `scripts/stargate` (dispatcher: "only `init` is
  wired; export/import/wipe rejected as unknown subcommands"), arch
  §13.3 ("wipe ships in a later feature"), and `files_budget: 12` shows
  the three lifecycle subcommands are explicitly deferred and cannot fit
  a "repair" ticket. acceptance #5 is satisfied by (a) extracting the
  authoritative compose-command builder (project name + compose file +
  env file) into `scripts/lib/compose.sh` so `init` uses it NOW and
  export/import/wipe WILL use it when shipped, and (b) updating
  quickstart.md's token/restart/teardown/manual-volume-removal to use
  the SAME project-scoped identity + env-file convention. The T092
  amendment's "export/import/wipe handle the pepper" is a forward
  contract recorded for those future subcommands; THIS ticket's pepper
  deliverable is `init`-time provisioning only.
- **Env file is functionally empty post-T094a — convention established
  anyway.** `compose/docker-compose.local.yml` now contains NO `${...}`
  substitutions (T094a removed the docker-socket-proxy, the last
  external image). B1's specific "`${DOCKER_SOCKET_PROXY_IMAGE}`
  expands to empty string" failure mode therefore no longer fires. But
  acceptance #2 still mandates the convention, so `init` ensures
  `compose/env/local.env` exists (created from `local.env.example` if
  absent; already gitignored at `.gitignore:37`) and always passes
  `--env-file compose/env/local.env`. This future-proofs the surface and
  is what the fixture test's env-loading assertion exercises.
- **Pepper path: `/etc/stargate/keys/pepper.key` (specs amended by redteam
  mandate).** data-model §1.7 originally listed `/etc/stargate/pepper.key`
  "mounted from the stargate-keys volume ... alongside the inter-plane
  ed25519 keypairs." The keypairs live at `/etc/stargate/keys/cp.priv` (the
  keys volume's mount point per compose lines 69/117); the literal
  `/etc/stargate/pepper.key` would land in the read-only
  `stargate-control-config` mount for the CP (unwritable). Grounding
  initially reconciled this as "no spec amendment; implement the intent."
  The stargate-redteam pass (Major #2) correctly flagged that as a live
  contract drift: consumers T035/T041/T044 `os.ReadFile` the spec's literal
  path and would fail-closed (DoS) or, on a lenient handler, HMAC with an
  empty pepper (forged-token auth). The impl + `tests/contract/internal/
  dpharness/auth.go` already use `/etc/stargate/keys/pepper.key`, so the
  SPECS were the stale side. This ticket amends data-model §1.7 + THREAT-
  MODEL §5.14 + SECURITY-DECISIONS.md + arch §9.1 + socks5-auth.md +
  T035/T041/T044 to `/etc/stargate/keys/pepper.key`, eliminating the drift.

## Acceptance

1. Write the Docker-backed regression test first. It uses tiny fixture images
   and proves env loading, project isolation, physical-volume resolution,
   ownership/mode for keys, IPC, CP state, DP state, and Tor config, plus
   idempotent reruns and `docker compose ps -q <service>` health discovery.
2. `scripts/subcommands/init` invokes one authoritative Compose command that
   always supplies the local env file and explicit project name.
3. Volume initialization resolves project-scoped physical names by Compose
   labels/rendered configuration; no literal `stargate-*` physical name is
   assumed.
4. The key volume remains fail-closed: existing keys are preserved, partial
   keysets fail, and permissions match the inter-plane contract.
5. Quickstart token, restart, teardown, and wipe commands use the same Compose
   identity and env-file convention.
6. The targeted regression test and `scripts/verify.sh` pass.

## Out-of-scope

Tor config startup ordering is T089/T087. Token-verifier key material is T092;
this ticket provisions any install-time secret shape that T092 has already
made authoritative without designing that shape itself.

## Notes

The regression test must fail against the pre-fix installer for the reasons in
review B1, then pass after the implementation in this ticket.

**T092 amendment (2026-07-15) — pepper provisioning is authoritative.**
T092 makes the install-time pepper shape authoritative
(`specs/001-tor-route/data-model.md` §1.7). This ticket provisions it,
per its existing out-of-scope note ("this ticket provisions any
install-time secret shape that T092 has already made authoritative"):
`init` step 3 generates `/etc/stargate/keys/pepper.key` via
`openssl rand -out <file> 32` (arch §9.1 step 3, amended; the spec's
`openssl rand -bytes 32` shorthand is not valid openssl CLI — real form
`openssl rand -out <f> 32`), mode `0640`, owned by the reading plane UID,
group `stargate-ipc` (GID 5100) — the same
ownership/mode scheme as the ed25519 inter-plane keypairs in the
`stargate-keys` volume. `export` must include it (warn the bundle carries
a secret), `import` restores it verbatim, `wipe` removes it alongside
keys and state, and rotation (re-pepper → re-HMAC every configured token
→ bump generation) is operator-initiated. The regression test should
cover pepper ownership/mode alongside the existing key-volume checks
(acceptance #4).
