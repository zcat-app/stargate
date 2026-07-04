---
id: T014
title: 'Author `sidecars/tor/Dockerfile`'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T014
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: ['spec.md#FR-015', 'constitution.md#IV', 'contracts/torrc.md']   # filled at /start
decision_refs: []
reviews: { round: 1, date: 2026-07-04, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T014: Author `sidecars/tor/Dockerfile`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `sidecars/tor/Dockerfile` — pinned `debian:12-slim` base by sha256 digest, installs `tor` from `deb.torproject.org`, verifies the apt-repo signing key at build time against `sidecars/tor/apt-key.fingerprint` (per FR-015), drops privileges to a non-root `tor` user, declares `HEALTHCHECK` parsing for "Bootstrapped 100%" against `Log notice stdout` from the rendered config.

## Analysis

**Pins (empirically resolved at /start from authoritative live sources, not invented):**

- Debian base: `debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df` — multi-arch OCI index, created 2026-06-23, resolved via `docker buildx imagetools inspect` (registry-direct, not local cache).
- Tor apt key fingerprint: `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89` — published at `https://deb.torproject.org/torproject.org/` where the filename IS the fingerprint (canonical Tor Project convention); key last modified 2025-08-08.
- Current Tor (bookworm suite): `0.4.9.11-1~d12.bookworm+1`, suite last updated 2026-07-03. The Dockerfile does not pin a specific Tor version — security updates flow via the repo; build-time reproducibility comes from the digest-pinned base + verified apt key.

**Must hold** (Constitution Principle IV — Pinned, Tested, Manually Promoted; FR-015):

1. **Base pinned by digest.** `FROM debian:12-slim@sha256:...` — never a bare tag. ground-check.sh fails the build on an un-pinned base.
2. **Tor from `deb.torproject.org`, not a fork.** FR-015 mandates the Tor Project's official Debian repo, not Debian's packaged `tor` (which lags) and not a third-party fork.
3. **Apt key fingerprint pinned AND verified at build time.** `sidecars/tor/apt-key.fingerprint` holds the canonical fingerprint string; the Dockerfile fetches the key, computes its fingerprint, and `diff`s against the pinned file — build fails on mismatch (TOFU resistance; FR-015 last clause).
4. **Drops to a non-root `tor` user** before ENTRYPOINT (Principle VI — auditable least privilege; the task body and T015's prose both name the runtime user `tor`).
5. **HEALTHCHECK detects "Bootstrapped 100%".** Implemented via the control port, not literal stdout-grep: historical stdout lines are not readable from inside the container (`/proc/1/fd/1` yields only *new* lines after the reader opens), so a stdout-grep healthcheck would silently fail forever once bootstrap completes. The control-port probe (`GETINFO status/bootstrap-phase` over cookie auth) is the only robust in-container mechanism; the contract already enables it (`ControlPort 0.0.0.0:9051`, `CookieAuthentication 1`, `CookieAuthFileGroupReadable 1`). The contract's `Log notice stdout` directive is preserved unchanged; it remains the source of operator-visible logs via `docker logs`.
6. Apache 2.0 SPDX header on the Dockerfile.

**Gated** (verify.sh catches fail-closed):

- License header → `check-license-headers.sh` (picks up `*Dockerfile`).
- ground-check.sh surfaces the digest pin + the Tor apt source for human confirmation; FAILs only on a structurally broken pin (bare tag, malformed digest).
- **No image build in verify.sh.** The Dockerfile is not built by any verify.sh gate; CI does not currently `docker build` it. Build correctness is exercised by downstream tests: T019b (Tor port exposure) and T022 (peer-dial invariants) bring up the image via `compose/docker-compose.local.yml`.

**Residue** (no gate catches; routed to `stargate-redteam` at this ticket):

- **No standing build gate.** A future edit to this Dockerfile that breaks the build (typo in apt source, removed key URL) would not be caught by verify.sh — only by T019b/T022 at integration time. This review is the standing gate for image-provenance properties until a `docker build` step is added to verify.sh or a release-cadence reproducibility test.
- **Healthcheck is control-port-based, not stdout-based.** Documented departure from the task body's literal "parsing for 'Bootstrapped 100%' against `Log notice stdout`"; the contract's stdout logging is preserved unchanged. Redteam must confirm the control-port probe is at least as strong as a stdout-grep would have been (it is: `GETINFO status/bootstrap-phase` is the authoritative source Tor itself uses to report bootstrap state; stdout `Bootstrapped 100%` is derived from the same internal state).
- **Tor version floats with the repo.** Builds are not bit-reproducible across time (a build today gets 0.4.9.11; a build next month may get 0.4.9.12). Acceptable per FR-015 (security updates must flow); the final composed image is digest-pinned in `compose/docker-compose.local.yml` (T015), which is the actual deployment-time pin.

## Acceptance

**Artefacts (2 files):**

- `sidecars/tor/Dockerfile` — `FROM debian:12-slim@sha256:60eac75...`, adds the Tor apt repo with key fingerprint verified against `apt-key.fingerprint`, installs `tor` (+ the single healthcheck runtime dep `netcat-openbsd` for the control-port probe; `od`/`tr`/`printf`/`grep` come from the Debian-slim base's coreutils), creates a non-root `tor` user, `USER tor`, `ENTRYPOINT ["tor"]`, `HEALTHCHECK` via control-port cookie-auth probe.
- `sidecars/tor/apt-key.fingerprint` — single line: `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`.

**Spec-fidelity floor:**

- Base digest-pinned (Principle IV / FR-015).
- Apt key fingerprint verified at build time (FR-015 last clause) — Dockerfile computes the fetched key's fingerprint and `diff`s against `apt-key.fingerprint`; non-zero exit fails the build.
- `USER tor` before ENTRYPOINT (non-root).
- HEALTHCHECK command parses `GETINFO status/bootstrap-phase` response for `PROGRESS=100`.

**Runnable command:** `bash scripts/verify.sh` GREEN (license-header gate picks up the Dockerfile; ground-check surfaces the digest pin). Full image build is exercised at integration time by T019b + T022, not by verify.sh.

## Out-of-scope

- Final composed image digest pin in `compose/docker-compose.local.yml` — T015.
- SECURITY-DECISIONS.md trust rationale for `deb.torproject.org` — T017.
- The torrc renderer — separate task (control plane); the contract is `specs/001-tor-route/contracts/torrc.md`.
- Adding a `docker build` step to verify.sh — separate hardening ticket; residue acknowledged above.
- Switching the healthcheck to literal stdout-grep — see §Analysis must-hold #5; not viable in-container.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
