# BUILD-DIFFS.md — expected reproducibility variance

> Constitution Principle VI requires that builds be reproducible and that
> **expected** variations be documented "so auditors verify only the
> unexpected diffs." This file is the canonical record of those expected
> variations. An auditor comparing two builds of the same source commit
> should treat entries here as known-acceptable and focus on anything else.

## Tor sidecar image (`stargate/tor`)

**Gated property — stable.** A clean rebuild (`docker build --no-cache`)
selects a **byte-stable package manifest**: the same set of packages at the
same versions every build (96 packages as of the T099 pin), including `tor`
and its full link-time closure (`libssl3`, `libevent-2.1-7`, `zlib1g`,
`libc6`). This is asserted at release cadence by
`tests/reproducibility/tor_sidecar_manifest_test.sh` and is the load-bearing
reproducibility guarantee (Constitution Principle IV). It holds because the
Debian archive is pinned to an immutable `snapshot.debian.org` run with
explicit `=version` pins (T099).

**Expected variance — final image DIGEST is NOT byte-stable.** Two cold
rebuilds of the same source commit produce different image IDs (config
sha256), e.g. `sha256:e91403a6…` vs `sha256:25799177…` (observed at T099
grounding). The known sources of this variance:

- **Image config `created` timestamp.** The legacy Docker builder embeds the
  wall-clock build time in the image config JSON; the config hash (and hence
  the image ID) derives from it.
- **Layer history timestamps.** Each layer's `created` field in the history
  records when its `RUN` executed.
- **dpkg status / postinst nondeterminism.** `dpkg` writes mtimes and
  `/var/lib/dpkg/status` entries whose ordering or timestamps are not
  byte-stable across runs; some package postinst scripts record state.

The **filesystem content (rootfs diffIDs) is expected to be stable or
near-stable** — the package bytes are identical — but the image *config*
varies, so the image *digest* varies.

**What an auditor should do.** Do NOT treat a differing `stargate/tor` image
digest across two builds as a defect on its own. Verify instead that:

1. The package manifests match (run
   `tests/reproducibility/tor_sidecar_manifest_test.sh`).
2. The snapshot run timestamp + every `=version` pin in
   `sidecars/tor/Dockerfile` agree with `SECURITY-DECISIONS.md` (run
   `tests/contract/security-decisions/tor_build_inputs_test.sh`).
3. Tor's documented behavioural invariants hold (run the live sidecar gate,
   `tests/contract/torrc/live_sidecar_test.go`).

If those three pass, the build is reproducible to the degree v1 promises.
Pursuing a byte-stable image *digest* (via `docker buildx` reproducible
builds + `SOURCE_DATE_EPOCH` + reproducible-layer discipline) is deferred to
the release workflow (T081) if a downstream verifier requires it.
