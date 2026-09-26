# BUILD-DIFFS.md — expected reproducibility variance

> Constitution Principle VI requires that builds be reproducible and that
> **expected** variations be documented "so auditors verify only the
> unexpected diffs." This file is the canonical record of those expected
> variations. An auditor comparing two builds of the same source commit
> should treat entries here as known-acceptable and focus on anything else.

## JVM control plane (`control-plane/`)

**Gated property — byte-identical.** Two clean `mvnw clean package` builds
of the same source bytes produce byte-identical build outputs — every jar
(module jars, the Quarkus runner jar, the fast-jar layout), every `.class`
file, gRPC stubs included — even when source mtimes are deliberately
perturbed per-file. Asserted by `tests/reproducibility/jvm_test.sh`
(release cadence, `STARGATE_VERIFY_REPRO=1`). The mechanism:
`project.build.outputTimestamp` pinned to `1980-01-01T00:00:00Z` in the
parent POM (maven-archiver's reproducible mode: fixed entry timestamps,
sorted entries, canonical file modes) plus
`io.github.zlika:reproducible-build-maven-plugin` at the parent reactor,
both per arch §12.2 and Constitution Principle VI. Any difference between
two JVM builds of the same commit is a defect, not expected variance.

**Expected variance — build-bookkeeping scratch, not artefacts.** An
auditor diffing raw `target/` trees will see two files vary per build:

- `api/target/quarkus-grpc<random>.sh` — protoc invocation scratch left in
  the module target root by quarkus-grpc codegen. Random per-build name,
  embeds host paths (JVM home, local `~/.m2`), and is never packaged into
  any jar. Excluded from `jvm_test.sh`'s comparison for exactly this
  reason.
- `*/target/maven-status/` — compiler input-file bookkeeping; not shipped.

**Native image (`-Pnative`)** is Constitution Principle VI's best-effort
tier and is outside `jvm_test.sh`. When native builds land, their expected
variations (build IDs, embedded timestamp metadata) are documented here
per that tier; JVM bytecode itself must always compare equal.

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

**Tor package content — independently checked (T160/T177).** A package-name/version
manifest alone cannot detect same-version replacement. The upgraded Tor
`0.4.9.13-1~d12.bookworm+1` also has reviewed amd64/arm64 `.deb` hashes in
`sidecars/tor/tor-packages.sha256`. The build downloads into a private apt cache,
checks the Tor artifact, resolves dependencies with only the Debian snapshot
source enabled, and disables downloads during installation. Repository priorities
alone do not isolate the source of same-version packages. Audit both
the package-manifest comparison and that pre-install content check; the negative
controls in `tests/contract/security-decisions/tor_package_integrity_test.sh`
must reject substituted bytes. Ground future locks against signed metadata and
actual packages as recorded in the dated T177 SECURITY-DECISIONS entry.

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
4. The independently pinned Tor package passed its build-time content check
   before offline installation, with the T160/T177 substitution/re-fetch and higher-/same-version
   dependency-source controls passing. The mutable Tor index must not supply dependencies.

These checks establish the stated package-selection tier; unexplained content
differences still block promotion under Constitution VI. They do not prove image-byte equality.
Pursuing a byte-stable image *digest* (via `docker buildx` reproducible
builds + `SOURCE_DATE_EPOCH` + reproducible-layer discipline) is deferred to
the release workflow (T081) if a downstream verifier requires it.
