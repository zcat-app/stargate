---
id: T087
title: 'Fix tor sidecar DataDirectory mismatch (HEALTHCHECK+ENTRYPOINT)'
status: done
created: 2026-07-11
last_updated: 2026-07-13
source: review/sol-review.md#B2+M3
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T089]
parallel: true
files_budget: 7
privacy_critical: true
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - spec.md §FR-014
  - spec.md §FR-011
  - contracts/torrc.md §"Invariants" row 11
decision_refs: []
reviews: { round: 2, date: 2026-07-13, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-07-11
  verdict: PASS
  discovered_by: T032
---

# T087: Fix tor sidecar DataDirectory mismatch (HEALTHCHECK+ENTRYPOINT)

## Context

Discovered by T032 at /start (recorded in T032 §Residue). The tor sidecar
image's ENTRYPOINT runs `tor -f /etc/tor/torrc` WITHOUT
`--defaults-torrc /etc/tor/torrc-defaults`, so Debian's defaults file
(which would set `DataDirectory /var/lib/tor`) is never loaded. Tor falls
back to its compile-time default of `$HOME/.tor` = `/var/lib/tor/.tor` for
USER tor (HOME=/var/lib/tor). The cookie lands at
`/var/lib/tor/.tor/control_auth_cookie`, not the
`/var/lib/tor/control_auth_cookie` that the Dockerfile HEALTHCHECK and
three documents assume.

## Impact

The Dockerfile HEALTHCHECK (sidecars/tor/Dockerfile:136) hardcodes
`/var/lib/tor/control_auth_cookie` and would therefore ALWAYS fail. Under
FR-014, a persistent UNHEALTHY verdict from the healthcheck drives
`routeEnableMask[TOR]` to DISABLED → ROUTE_DOWN for every Tor-routed
request. This breaks the entire Tor route at the healthcheck layer before
any data-plane forwarder (T047) or contract test (T058/T058a) can
exercise it.

THREE documents carry the now-known-wrong path:
- `sidecars/tor/Dockerfile:136` (HEALTHCHECK cookie path)
- `specs/001-tor-route/data-model.md:336` (cookie path in volume table)
- `specs/001-tor-route/contracts/torrc.md` invariant #11 comment ("default
  `/var/lib/tor` from the Debian package" — this is the torrc-defaults
  default, NOT the compile-time default that applies when torrc-defaults
  is not loaded)

## Acceptance

1. Write a cold-volume regression test first. Start the production Tor image
   without seeding config from the harness and assert Docker reports
   `State.Health.Status == healthy`.
2. Implement T089's amended contract: the image contains the byte-pinned safe
   `torrc` (the `wantTorrc` golden from `contracts/torrc.md` §"Rendered file")
   baked in at `/etc/tor/torrc` before the entrypoint runs, including explicit
   `DataDirectory /var/lib/tor`; Tor does not wait for CP rendering
   (`sidecars/tor/Dockerfile` COPY + ENTRYPOINT; `compose/docker-compose.local.yml`
   drops the v1 boot dependency on `stargate-tor-config`).
3. Assert the loaded configuration contains every torrc contract invariant,
   the control cookie is exactly `/var/lib/tor/control_auth_cookie`, and the
   SOCKS/control ports remain compose-internal.
4. Update the Docker healthcheck to read the authoritative cookie path and
   perform the authenticated bootstrap probe.
5. T089 already amended `contracts/torrc.md`, `data-model.md` §6,
   `SECURITY-DECISIONS.md`, and the T029/T030 goldens (lock-step) — do NOT
   re-amend them here. T087's remaining test/code work: update
   `tests/contract/torrc/live_sidecar_test.go` (T032) to stop seeding the
   `stargate-tor-config` volume (the torrc is image-baked now) and to assert
   `State.Health.Status == healthy`; remove `find`-based test workarounds
   that could mask a path regression; update `sidecars/tor/Dockerfile` and
   `compose/docker-compose.local.yml` per acceptance #2.
6. T032, the new cold-volume test, and `scripts/verify.sh` pass.

## Out-of-scope

- T062 (Go-side control-port client with cookie volume mount) — separate
  Phase 4 ticket.
- Any change to the IsolateSOCKSAuth / IsolateClientAddr directives
  themselves — those are invariant #1, untouched here.

## Notes

Filed by T032 round-1 review (stargate-codereview finding 2). The T032
test works around this via `find /var/lib/tor -name control_auth_cookie`
(robust to any DataDirectory), so T032 is not blocked by this defect.
T087 is `risk: high` because it touches the tor image's ENTRYPOINT,
which is the highest-trust artefact in the stack (sidecars/tor/Dockerfile
header: "this front mounts the persisted onion signing key... its image
is the highest-trust artifact in the stack"). A redteam pass is
recommended before merge given `privacy_critical: true`.

## Analysis

Property map (privacy_critical: true → required per
`docs/process/analysis.md`). T089 already amended the contract documents
(`contracts/torrc.md`, `data-model.md` §6, `SECURITY-DECISIONS.md`, the
T029/T030 goldens) to the image-baked-torrc posture; T087 lands the
code/test side and must NOT re-amend those docs. The residue items below
are all **promoted** into the gated set (Docker cadence) by T087's
cold-volume + live test additions — the residue left over for redteam is
the build-time trust surface and the mount-shadowing regression vector.

- **Must hold:**
  - The image-baked `/etc/tor/torrc` is byte-for-byte equal to the
    `wantTorrc` golden pinned by T029 (FR-011; invariant #13 — single
    trailing LF, no CRLF).
  - `DataDirectory /var/lib/tor` is explicit in the baked torrc, so Tor
    does NOT fall back to its compile-time default of `$HOME/.tor` =
    `/var/lib/tor/.tor` (invariant #11; sol-review B2+M3).
  - The control cookie lands at exactly `/var/lib/tor/control_auth_cookie`
    — deterministic from the explicit DataDirectory, matching the
    Dockerfile HEALTHCHECK and T062's future control-port helper.
  - The tor service does NOT mount `stargate-tor-config` at `/etc/tor` for
    v1 boot — a `:ro` volume mount at `/etc/tor` would SHADOW the
    image-baked torrc (Constitution Principle II — no CP render
    dependency; sol-review B2).
  - Tor startup never waits for the control plane: ENTRYPOINT loads the
    image-baked `/etc/tor/torrc`; compose drops the v1 boot dependency on
    `stargate-tor-config` (Principle II).
  - The Dockerfile HEALTHCHECK reads the authoritative cookie path
    (`/var/lib/tor/control_auth_cookie`) and performs the authenticated
    bootstrap probe (`AUTHENTICATE` + `GETINFO status/bootstrap-phase` +
    grep `PROGRESS=100`) — FR-014's `UNHEALTHY` verdict drives
    `routeEnableMask[TOR]` to DISABLED, so a broken healthcheck breaks the
    whole Tor route at the healthcheck layer.
  - A cold-volume start (production image, no harness-seeded config)
    reaches Docker `State.Health.Status == healthy` (acceptance #1).
  - The loaded configuration (GETCONF over the live control port) contains
    every torrc contract invariant; SOCKS/control ports remain
    compose-internal (acceptance #3; FR-012; invariant #2).
- **Gated:**
  - `contracts/torrc.md §"Rendered file"` == `wantTorrc` golden: gated by
    `TestRenderedTorrcByteMatch` (T029, hermetic PR gate).
  - Per-invariant rows 1–13 on the golden: gated by `invariants_test.go`
    (T030, hermetic PR gate).
  - No-bridges substring sweep: gated by `no_bridges_test.go` (T031,
    hermetic PR gate).
  - Compose structure (7 volumes, tor has no host ports, DP loopback-only):
    gated by `local_compose_test.sh` (T015, hermetic PR gate). T087
    updates M7 to assert tor does NOT mount `stargate-tor-config` (the
    mount would shadow the image-baked torrc) while the volume stays
    declared + CP-mounted (dormant, for future T037).
  - License headers: gated by `scripts/check-license-headers.sh`.
  - Go compile of `//go:build docker` tests: gated by
    `go vet -tags docker` in `scripts/go-workspace-gate.py` (hermetic PR
    gate; the docker-tagged tests RUN in the named Docker job).
- **Residue:**
  - The image actually bakes `/etc/tor/torrc` byte-for-byte equal to the
    golden — no hermetic gate reads a file out of a built Docker image.
    **Promote**: T087's cold-volume regression test reads
    `/etc/tor/torrc` from the production image (no harness seeding) and
    asserts byte-equality with `wantTorrc` (Docker cadence).
  - Tor actually loads the baked torrc and reaches
    `State.Health.Status == healthy` — no hermetic gate starts the Tor
    image. **Promote**: T087's cold-volume test asserts Docker health
    == healthy (Docker cadence).
  - The control cookie lands at exactly `/var/lib/tor/control_auth_cookie`
    (not `/var/lib/tor/.tor/...`) — only a live test catches a
    DataDirectory regression; the prior `find`-based workaround masked
    exactly this regression. **Promote**: T087's live test asserts the
    cookie file exists at the exact path with no `find` fallback (Docker
    cadence).
  - The loaded config contains every torrc invariant at runtime — GETCONF
    over the live control port. **Promote**: T087's live test issues
    GETCONF for each directive and compares to the golden's expected
    value (Docker cadence).
  - Residue left over (redteam scope): the Dockerfile ENTRYPOINT is the
    highest-trust artefact; a build-pipeline compromise (MITM on
    deb.torproject.org, key rotation) could inject a malicious tor binary
    or swap the torrc after the contract test runs but before image push.
    Mitigated by the keyring stage (fingerprint + PUB_COUNT==1) and
    final-image digest pinning at release-tag time (T017); residue until
    then. The mount-shadowing regression (a future ticket re-adding a
    `/etc/tor` mount) is caught by the updated `local_compose_test.sh` M7
    at PR cadence.
