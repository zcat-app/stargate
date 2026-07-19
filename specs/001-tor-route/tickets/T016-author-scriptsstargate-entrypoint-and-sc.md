---
id: T016
title: 'Author `scripts/stargate` entrypoint and `scripts/subcommands/init` de'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T016
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh
parallel: false
files_budget: 4
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §9 (scripts/stargate init Behaviour)
  - specs/000-architecture/spec.md §9.1 (Steps)
  - specs/000-architecture/spec.md §9.2 (Failure modes)
  - specs/000-architecture/spec.md §9.3 (Idempotence guarantees)
  - specs/000-architecture/spec.md §4.3 (inter-plane keys: cp.priv/dp.priv 0600, cp.pub/dp.pub 0644)
  - specs/001-tor-route/research.md §8 (Scope split for init in this feature)
  - specs/001-tor-route/contracts/control-grpc.md §"Socket topology" (UID/GID numerics)
decision_refs:
  - research.md §8
constitution_refs:
  - "III: No outbound except routed request"
  - "IV: Reproducibility / supply-chain pins"
  - "VII: Tests-first for privacy-critical paths"
reviews: { round: 1, date: 2026-07-04, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings:
  - "2026-07-04: CLEAN (0 BLOCKER / 0 MAJOR / 3 MINOR / 5 INFO). Addressed pre-commit: MINOR1 (STARGATE_KEYGEN_IMAGE override now runtime-guarded to require @sha256: + gated by contract test), MINOR3 (--profile=VALUE equals form rejected; test covers both forms), INFO1+5 (M5 probe rewrite — count-based, distinguishes 0/4/partial, clean exit status), INFO3 (ulimit -c 0 in generate_keys). Deferred: MINOR2 (flock concurrency guard — portability concern util-linux/macOS, rare under THREAT-MODEL §3.1 single-user local; revisit at LAN-profile feature), INFO2 (SIGKILL mid-generation residue — accepted R6), INFO4 ($BASH trust — parent already has code-exec parity)."
clarity_check: {}
---

# T016: Author `scripts/stargate` entrypoint and `scripts/subcommands/init`

## Context

Derived from `specs/001-tor-route/tasks.md` T016 / `research.md` §8. Ships the
**minimum subset** of the operator-facing `stargate init` command
(arch §9.1) needed to bring up the local-profile stack for this feature:
preflight → ed25519 key generation into `stargate-keys` → hard-coded
`compose/docker-compose.local.yml` up with bounded healthcheck wait → Tor-only
verification → status table → stable exit codes (10/20/30/40/50). Everything
else in arch §9.1 (profile selection, admin enrollment, `--force`/`--repair`,
`export`/`import`/`wipe`) is deferred to later features (see §Out-of-scope).

T015 landed the compose file this script drives; T016 is the operator entry
point that makes it runnable end-to-end. T017/T017a/T018 land the
SECURITY-DECISIONS + arch amendments that reference this command.

> **Full task body (verbatim from tasks.md):**
>
> Author `scripts/stargate` entrypoint and `scripts/subcommands/init` delivering the minimum subset per research.md §8: preflight, ed25519 key generation into `stargate-keys` volume (private keys `cp.priv` mode 0600 owned `stargate-cp`, `dp.priv` mode 0600 owned `stargate-dp`; public keys `cp.pub` and `dp.pub` mode 0644 — public material, both planes must read both pubs for the mutual handshake), hard-coded `compose/docker-compose.local.yml`, bounded healthcheck wait, Tor-only verification, status table, stable exit codes (10/20/30/40/50).

## Analysis

Property map (per `docs/process/analysis.md`), grounded against
`compose/docker-compose.local.yml` (T015), the three Dockerfiles
(`data-plane/`, `control-plane/`, `sidecars/tor/`), arch §9.1–§9.3 + §4.3,
research §8, and `contracts/control-grpc.md §"Socket topology"`.

### Must hold

- **M1 — Dispatcher.** `scripts/stargate` is a thin shell dispatcher: routes
  `init` → `scripts/subcommands/init`; unknown subcommand and no-args print
  usage to stderr and exit non-zero; `--help`/`-h` prints usage to stdout and
  exits 0. (arch spec §3 file tree note: "`scripts/stargate` is a thin shell
  dispatcher to subcommand scripts; language choice is shell to keep zero
  runtime deps for ops tooling.")
- **M2 — Step coverage + ordering.** `scripts/subcommands/init` implements the
  research §8 minimum subset in arch §9.1 order: preflight → (profile=local,
  hard-coded) → key generation → compose-up (bounded healthcheck) → Tor-only
  verification → status table → exit. No step is silently dropped.
- **M3 — Preflight gates.** Preflight verifies `docker` present, `docker
  compose v2` present (`docker compose version` succeeds), and the Docker
  socket reachable (`docker info` or equivalent succeeds). Any failure →
  exit 10. (arch §9.1 step 1, §9.2 "Docker missing → exit 10".)
- **M4 — Key ownership/perms contract.** Key generation writes exactly four
  files into the `stargate-keys` named volume: `cp.priv` mode `0600` owned
  `5101:5100` (stargate-cp), `dp.priv` mode `0600` owned `5102:5100`
  (stargate-dp), `cp.pub` mode `0644`, `dp.pub` mode `0644`. The UID/GID
  literals MUST match `control-plane/Dockerfile` (`useradd --uid 5101`,
  `groupadd --gid 5100`), `data-plane/Dockerfile` (`stargate-dp:x:5102:5100`),
  and the compose `user:` literals (`"5101:5100"`, `"5102:5100"`). (arch §4.3;
  task body; T015 compose file.)
- **M5 — Idempotence / key safety.** `init` MUST NOT regenerate keys if
  `stargate-keys` is already populated (arch §9.3: "init MUST NOT regenerate
  inter-plane keys if `stargate-keys` is populated — doing so would
  invalidate enrolled devices"). Re-run against an initialized stack skips
  key-gen and proceeds (or no-ops per §9.3). No `--force` in this subset
  (deferred).
- **M6 — Hard-coded local profile.** The compose file path is hard-coded to
  `compose/docker-compose.local.yml`; no `--profile` flag, no profile prompt
  (research §8: "local only in this feature"). The string literal appears
  exactly once as the authoritative path.
- **M7 — Bounded healthcheck wait.** Compose-up waits for each container's
  healthcheck with a bounded budget (default 60 s, arch §9.1 step 4),
  overridable via a documented env var (e.g. `STARGATE_HEALTHCHECK_TIMEOUT`).
  Timeout → exit 40, and containers are LEFT UP so the operator can inspect
  `docker logs` (arch §9.2: "leave containers up"). `init` MUST NOT `docker
  compose down` on healthcheck failure.
- **M8 — Tor-only verification.** The verification step probes ONLY the Tor
  route surface (no I2P / Nym / Direct port literals, no admin-UI probe —
  those sidecars/routes are out of scope this feature). Verify failure →
  exit 50. (research §8: "delivered for the Tor SOCKS5 endpoint only; other
  sidecars are not in scope.")
- **M9 — Status table.** On success, init renders a status table covering
  exactly the components present in the local profile (data plane, control
  plane, Tor sidecar). No placeholder rows for absent sidecars. (arch §9.1
  step 6 shape; research §8 "components present in this feature".)
- **M10 — Stable exit codes.** Exit codes are the stable contract surface
  from research §8 / arch §9.1 §7: `0` success; `10` preflight; `20`
  key-generation; `30` compose (-up / build); `40` healthcheck; `50` verify.
  Codes appear as named literals/constants, not magic numbers scattered
  through control flow.
- **M11 — Private-key hygiene.** Private key material (`cp.priv`, `dp.priv`)
  is written only into the `stargate-keys` named volume; no copy is left in a
  host-readable temp dir, a build context, or stdout/log output. Temp dirs
  used during generation are cleaned up (trap on EXIT/INT/TERM). (Principle
  III spirit; key-handling hygiene.)
- **M12 — No outbound except docker daemon + image pulls.** The script opens
  no outbound network connection except (a) the Docker daemon socket and
  (b) image pulls the daemon performs for compose build / the key-gen helper
  container. No telemetry, no version-check-home call, no "is there a newer
  Stargate?" lookup. (Constitution Principle III; AGENTS.md "No outbound
  network connections from Stargate except those a request explicitly routes
  through" — the init script inherits the same doctrine.)
- **M13 — License headers.** Both scripts and the contract test carry the
  Apache-2.0 SPDX header matching `scripts/check-license-headers.sh`.

### Gated (verify.sh catches fail-closed)

- **G1** — License-header gate (verify gate 1) → M13.
- **G2** — New structural contract test `tests/contract/stargate-cli/init_test.sh`
  (verify gate 4, auto-discovered) → M1, M2 (step/dispatch structure), M3
  (preflight logic present + exit-10 constant), M4 (perm/UID literals present
  AND cross-validated against the three Dockerfiles + the compose `user:`
  literals — same cross-file technique as T015's M6), M6 (hard-coded path
  literal, single occurrence), M7 (default 60 s bound + env-override literal
  + no-`down`-on-timeout), M9 (status table rendering for exactly DP/CP/Tor),
  M10 (all five exit-code constants present).
- **G3** — Behavioral preflight test (hermetic, inside G2): invoking the init
  subcommand with an empty `PATH` so `command -v docker` fails exits 10. Proves
  the exit-code wiring is live, not just textually present. (Part of M3.)

### Residue (no gate catches — redteam focus)

- **R1 — Key-gen runtime correctness.** G2 asserts the ownership/perm literals
  are textually present and cross-consistent, but does NOT prove a real
  `docker run` against a real `stargate-keys` volume produces `0600` files
  owned by `5101:5101`/`5102:5100`. A logic bug in the key-gen function (wrong
  `install` flag order, volume created after mount, missing `chown`, race with
  compose-up) passes the structural test. **Downstream gate:**
  `tests/contract/control-grpc/transport_test.go` (T022) requires correctly
  generated, correctly permissioned keys to complete the mutual-ed25519
  handshake — a broken key-gen fails the handshake there. R1 is caught at
  T022, not T016.
- **R2 — Key FORMAT compatibility.** T016 generates ed25519 keys in a chosen
  serialization (e.g. openssl PKCS#8 PEM). If that format does not load in
  one plane's TLS stack (Go `crypto/x509` for DP, Java PKCS#8 for CP), T016's
  own gate is silent. **Downstream gate:** T022 handshake (same path as R1).
  The implementer SHOULD pick PKCS#8 PEM (universally loadable by both
  stacks) and record the choice in §Notes.
- **R3 — Healthcheck-timeout leave-containers-up semantics (behavioural).**
  G2 asserts the script does not textually call `docker compose down` on the
  timeout path, but cannot prove at PR cadence that a real timeout leaves
  containers up (signal handling, `set -e` interaction). **Downstream gate:**
  a future runtime test or manual ops verification. Minimal — documented in
  code comments + §Notes; trust review + redteam.
- **R4 — Tor-only verify correctness (behavioural).** G2 asserts the verify
  step textually references only Tor-side literals (no `8882`/`8884`/`8885`
  port constants), but cannot prove the probe actually exercises the Tor
  route at runtime. **Downstream gate:** T019b (port exposure) + T019c
  (proxy lockdown) bring up the stack and exercise the Tor surface; a
  mis-scoped verify is caught there.
- **R5 — Key-gen helper image supply-chain pin (PROMOTED into the gate).** The
  implementation reuses the exact `debian:12-slim@sha256:...` digest already
  pinned in `sidecars/tor/Dockerfile` (both stages) for the chown-into-volume
  helper container. `tests/contract/stargate-cli/init_test.sh` cross-checks
  the two digests for equality (extending T015's cross-file technique), so
  drift between the script's pin and the canonical base digest fails the
  contract gate. Residual (not gated): the script's digest pin is still NOT
  scanned by `scripts/ground-check.sh` (which covers Dockerfile `FROM` and
  compose `image:` pins only) — so the online registry-resolution gate at
  release cadence does not cover it. A follow-up could extend ground-check's
  scanner to shell-script pins; until then the cross-check here catches
  drift, and the tor Dockerfile's own FROM pin is what ground-check resolves
  online.
- **R6 — Host temp-dir shredding on signal.** M11 requires temp-dir cleanup;
  G2 can assert a `trap`/cleanup literal is present but cannot prove no
  private-key byte survives a `SIGKILL` mid-generation. Minimal; the keys are
  regenerable and the temp dir under `mktemp -d` is mode 0700 on the host.
  Acceptable residue.

## Acceptance

- **AT-1 (tests-first, Principle VII).** Add
  `tests/contract/stargate-cli/init_test.sh` (a STATIC + hermetic-behavioural
  contract test, no `docker compose up`, no daemon containers — mirrors
  T015's `local_compose_test.sh` philosophy). It MUST pass under verify gate
  4 and assert, at minimum:
  - `scripts/stargate` and `scripts/subcommands/init` exist, are executable,
    and carry the SPDX license header (M1, M13).
  - **Dispatcher behaviour (M1):** `scripts/stargate` with no args exits
    non-zero and writes usage to stderr; `scripts/stargate init` dispatches
    (does not print "unknown subcommand"); an unknown subcommand exits
    non-zero.
  - **Preflight exit-10 (M3, behavioural + hermetic):** invoking the init
    subcommand with `PATH=` (empty) — so `command -v docker` fails — exits
    `10`.
  - **Exit-code constants (M10):** the literals `10`, `20`, `30`, `40`, `50`
    each appear as exit targets in `scripts/subcommands/init`.
  - **Hard-coded compose path (M6):** the string
    `compose/docker-compose.local.yml` appears in `scripts/subcommands/init`
    and `scripts/stargate` does NOT accept a `--profile` flag.
  - **Key ownership/perms (M4) + cross-file check:** the literals `0600`,
    `0644`, `5101`, `5102`, `5100` appear in `scripts/subcommands/init`; AND
    `5101`/`5100` appear in `control-plane/Dockerfile`, `5102`/`5100` in
    `data-plane/Dockerfile`, and `"5101:5100"`/`"5102:5100"` in
    `compose/docker-compose.local.yml`. (Drift across any pair fails the
    test.)
  - **Bounded healthcheck (M7):** a default timeout literal (60) and an
    env-override variable name appear; the substring `compose down` does NOT
    appear in `scripts/subcommands/init` (no teardown on failure).
  - **Tor-only verify (M8):** port constants `8882`, `8884`, `8885` do NOT
    appear in `scripts/subcommands/init`.
  - **Status table (M9):** the script renders a table referencing exactly
    the data plane, control plane, and Tor sidecar (no I2P/Nym/Direct rows).
  - **No outbound (M12):** no `curl`/`wget` of a remote URL literal appears
    in either script.
- **AT-2.** `scripts/verify.sh` is GREEN (the new contract test passes; no
  existing gate regresses).
- **AT-3 (residue acknowledgement, non-blocking).** §Analysis R1–R6 each map
  to a named downstream gate (T022 for R1/R2, T019b/T019c for R4, future
  runtime/ops for R3, the G2 cross-check or a follow-up for R5, review for
  R6). The implementer records the chosen key FORMAT and key-gen helper
  image decision in §Notes so T022's author inherits it.

## Out-of-scope

Per research §8, the following arch §9.1 surfaces are **deferred to later
features** and MUST NOT be implemented in T016:

- **Profile selection** (`--profile {local,lan,vps}`, WireGuard peer prompt).
  Local-only, hard-coded.
- **Admin enrollment URL / WebAuthn relying-party setup** — deferred to the
  admin-UI feature. `init` prints no enrollment code.
- **`--force` / `--repair`** and the interactive re-init prompt. M5 handles
  the safe case (skip key-gen if populated); destructive re-init is not
  shipped.
- **`export` / `import` / `wipe` subcommands** (arch §9 / file-tree note) —
  not authored. The dispatcher SHOULD reject them as unknown subcommands
  (they are not yet wired).
- **Verification of non-Tor routes** (I2P, Nym, Direct, IPFS-reserved) and
  the admin-UI `/admin` 401 probe — those routes/UI don't exist in this
  feature.
- **Extending `scripts/ground-check.sh` to scan shell-script image pins**
  (R5 follow-up). T016 either reuses the tor base digest (enabling the G2
  cross-check) or leaves R5 as documented residue; it does not expand
  ground-check's scanner.

Re-running `init` against an already-healthy stack (arch §9.3 no-op +
status-print) is in scope ONLY to the extent that M5 (do-not-clobber-keys)
requires detecting existing keys; full `--repair`/status-only modes are
deferred.

## Notes

- **Key FORMAT (R2) — recommended:** openssl PKCS#8 PEM for both planes
  (`openssl genpkey -algorithm ED25519` → priv; `openssl pkey -pubout` →
  pub). PKCS#8 is loadable by Go `crypto/x509.ParsePKCS8PrivateKey` and by
  Java `PKCS8EncodedKeySpec` without bespoke parsing in either plane. Record
  the final choice here at /implement so T022 inherits it.
- **Key-gen helper image (R5) — recommended:** reuse the exact
  `debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df`
  digest pinned in `sidecars/tor/Dockerfile` (both stages). debian:12-slim
  ships coreutils (`install`, `chown`, `chmod`) but NOT `openssl`, so the
  pattern is: generate on the host with `openssl` (preflight MUST verify
  `openssl` present, else exit 10) into a `mktemp -d` (mode 0700), then
  `docker run --rm -v stargate-keys:/keys -v "$tmp:/src:ro"
  debian:12-slim@sha256:... sh -c 'install -m 0600 -o 5101 -g 5100
  /src/cp.priv /keys/cp.priv; ...'`. G2 then cross-checks the script's digest
  equals the tor Dockerfile's base digest. If the implementer chooses a
  different image, document why and file the ground-check extension as a
  follow-up.
- **openssl as a host dependency:** arch §9.1 doesn't list it, but it is
  near-universal on Linux/macOS. Preflight MUST check `openssl` and exit 10
  if absent (fail loud, fail early — do not fall back to a weaker key).
  LibreSSL (macOS default) supports `genpkey -algorithm ED25519` on current
  releases; if the implementer finds a portability gap, switch to
  `ssh-keygen -t ed25519 -m PKC8` (OpenSSH ≥ 7.8) and record the choice.
- **Healthcheck**: `compose/docker-compose.local.yml` (T015) does not yet
  declare `healthcheck:` blocks on the services. The bounded wait in T016
  polls `docker inspect --format '{{.State.Health.Status}}'` (empty/none →
  treat as "started" fallback) OR falls back to `docker compose ps` status.
  The implementer SHOULD make the wait robust to "no healthcheck defined"
  (poll container running state) and document the heuristic here. Adding
  real `healthcheck:` blocks to the compose file is a SEPARATE ticket (would
  modify T015's contract surface) — do not edit the compose file in T016.
- **No `--profile` flag (M6):** the dispatcher parses only the subcommand
  token; flags after `init` are passed through but `--profile` is rejected
  (or ignored with a warning). Keep argument parsing hand-rolled and minimal
  — no `getopt`/`getopts` dependency beyond what the subset needs.
- **References:** arch §9.1–§9.3 (behaviour), §4.3 (key perms/ownership),
  research §8 (scope split), `contracts/control-grpc.md §"Socket topology"`
  (UID/GID numerics), T015 compose file (the file this script drives).
