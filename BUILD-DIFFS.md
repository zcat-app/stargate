# BUILD-DIFFS.md — expected reproducibility variance

> Constitution Principle VI requires that builds be reproducible and that
> **expected** variations be documented "so auditors verify only the
> unexpected diffs." This file is the canonical record of those expected
> variations. An auditor comparing two builds of the same source commit
> should treat entries here as known-acceptable and focus on anything else.

## Browser extension (`extension/`)

**Gated property — byte-identical on the same host.** Two builds of the same
extension source using the same host `zip` executable produce byte-identical
archives even when source mtimes and modes are perturbed. The release-cadence
gate `tests/reproducibility/extension_test.sh`
(`STARGATE_VERIFY_REPRO=1`) also checks the expected member set and
lexicographic order, canonical 1980-01-01 timestamps, Unix file modes
(`100644`), and absence of extra fields. `extension/package.sh` stages and
normalizes files before invoking the host `zip`; this test does not compare
different `zip` executables or versions.

**Expected variance — unpinned `zip` executable.** The repository does not pin
or record the `zip` executable used by `extension/package.sh`. Different
Info-ZIP builds or versions may therefore produce different compressed bytes
through deflate implementation changes, or different EFS/Unicode filename
flags for non-ASCII member names. The repository does not assert byte equality
across those versions.

**What an auditor should do.** Once T081 records the release build's `zip`
identity, compare releases built with the same recorded identity. When the
identity differs, differences confined to the documented compression or
EFS/Unicode-flag vectors are expected; unexplained differences remain defects.
Until T081 records that identity, do not infer which `zip` version produced a
release.

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
`libc6`). The snapshot run and `=version` pins (T099) select it but do not
hold it alone: snapshot InRelease files carry no Valid-Until, so an older
signed index can be replayed over HTTP. T184 makes it hold: every build
checks the snapshot InRelease hash and compares its installed closure with
the committed per-arch `sidecars/tor/package-closure.lock`, failing on any
difference. `tests/reproducibility/tor_sidecar_manifest_test.sh` asserts at
release cadence that cold rebuilds equal that lock and that a tampered lock
or replayed older index fails the build; this is the load-bearing
reproducibility guarantee (Constitution Principle IV).

**Tor-internal health publisher (T203).** This static Go executable is an additional
reviewed Tor-image input outside the Debian package manifest. The image uses the same
digest-pinned Go builder as the observer, locked modules, `CGO_ENABLED=0`, `-trimpath`,
`-buildvcs=false` and an empty build ID. The release-cadence Tor harness compares the
publisher bytes from both cold builds separately from package manifests. Matching Debian
manifests alone cannot establish publisher identity; a skipped release job makes no measured
byte-equality claim. Publisher and shared finite-record source, module locks, Dockerfile
and launcher belong to the candidate's executable closure.

**Tor package content — independently checked (T160/T177/T213).** A package-name/version
manifest alone cannot detect same-version replacement. The upgraded Tor
`0.4.9.14-1~d12.bookworm+1` also has reviewed amd64/arm64 `.deb` hashes in
`sidecars/tor/tor-packages.sha256`. The build downloads into a private apt cache,
checks the Tor artifact, resolves dependencies with only the Debian snapshot
source enabled, and disables downloads during installation. Repository priorities
alone do not isolate the source of same-version packages. Audit both
the package-manifest comparison and that pre-install content check; the negative
controls in `tests/contract/security-decisions/tor_package_integrity_test.sh`
must reject substituted bytes. T213 grounded both architecture artifacts in the
same currently signed official metadata; only amd64 was built and runtime-checked,
and package identity alone does not establish Tor behavior or route readiness.
The native image identity, exact build-wrapper/cleanup outcomes and bounded
package/torrc observation are recorded in `reviews/T213/README.md`.
Ground future locks against signed metadata and actual packages as recorded in
the dated T213 SECURITY-DECISIONS entry. The moving upstream index can still
remove this pin; subsequent clean builds then fail closed until another reviewed
manual promotion.

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
