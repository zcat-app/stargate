# Preparing and promoting a release

Copyright 2026 The Stargate Authors. SPDX-License-Identifier: Apache-2.0

The release workflow operates on an **existing reviewed version tag** and its exact
source commit C. Preparation does not publish, sign, create a tag or rewrite source.
Promotion consumes retained bytes and independent evidence; it never rebuilds.
Acceptance of T081's workflow implementation is not release authorization or a
claim that final review, real signatures, live tests or publication have occurred.

## Source and artifact boundary

Source Compose remains the development build entry point. Release Compose is a
generated JSON Compose document with exactly `stargate-dp`, `stargate-control`,
`tor` and `tor-observer`. Each image names a GHCR repository and registry digest;
build entries and `pull_policy: build` are removed. All other parsed source
topology is retained. A relative host bind mount requires an explicit future
implementation; it cannot silently change meaning in the release directory.

Feature 001 packages Linux amd64 Local images, amd64 and arm64 data-plane
binaries, the complete JVM fast-jar tree (including its launcher, app/lib/quarkus
directories and entrypoint), the extension ZIP and full source. Arm64 is a
cross-build comparison, **not runtime acceptance**. Native CP and additional
runtime profiles are not produced by this workflow. This packaging scope does
not discharge any live release obligation: R-1 through R-8, including R-7's
routed IPv6, LAN/VPS, physical NIC and hypervisor observations, remain required.
Unsupported or unmeasured scope blocks promotion; it is never N/A or PASS. R-2
cannot substitute for R-3 or R-7. The exact tracker text at C governs each report.

## Preparation

Dispatch `.github/workflows/release.yml` on the existing version tag with
`phase=prepare`, `version=vMAJOR.MINOR.PATCH` and the full 40-character `source=C`.
The selected workflow ref, workflow SHA, checkout HEAD and existing tag must all
agree. A branch dispatch or a mismatched source is not a preparation job.

Preparation uses a fresh `ubuntu-24.04` hosted job, with a 240-minute timeout.
That timeout is not measured runtime or capacity. Disk feasibility for the full
verifier, cold image builds, comparisons and retained artifact must be evaluated;
neither the artifact limits nor the workflow label establish sufficient capacity.
This task registers no runner and changes no host. Docker, its daemon and the
existing verifier's system prerequisites must work.
Source and release init accept only the default Docker context at the local
rootful `/var/run/docker.sock` or `/run/docker.sock`; a remote context, redirected
socket or rootless daemon refuses before host policy or provisioning.
The pinned setup action supplies Go, JDK, Python and Node. An absent required
tool is a refusal, not a release PASS. Actual resource needs/tool interoperability
must be measured in an explicitly authorized finite validation before use.

`scripts/release/inputs.json` identifies the selected Compose, Buildx, BuildKit,
SBOM generator, Crane, Cosign, Sigstore root bytes and fixed signing services. `install-tools` downloads
only the fixed public URLs and verifies lengths and SHA256 before installation.
Every execution rechecks the installed tool. For Crane, the verified upstream
archive is retained and its member is compared directly; a local receipt does
not replace the archive's pin. Tools live under `target/release-tools` and do
not replace host tools. Publisher metadata grounding does not prove runtime
compatibility of those exact binary bytes.

Preparation has only contents/read and actions/read grants. It refuses ambient
OIDC authority and verification narrowing. It runs the full `scripts/verify.sh`
with `STARGATE_GROUND_ONLINE=1` and `STARGATE_VERIFY_REPRO=1`. The log must contain
every expected gate. A package-level PASS cannot hide individual test skips.
The verifier uses a positively identified local Docker driver: its tagged test
images must load into the daemon, and Tor's host-network rollback build must
reach its loopback replay proxy. The separate source-pinned container builder
is used for retained OCI exports after that verifier; it is not selected for
the verifier's daemon-consumed tests. An unreachable proxy remains a failed
rollback control, not evidence of hash rejection.
No-test Go packages are distinguished from skipped tests using the source tree.
Only the driver's fixed, named cadence cases may remain pending; the candidate
records them explicitly and promotion requires their corresponding live/full
cadence reports. Missing prerequisites and arbitrary skip reasons are not waivers.

Four amd64 OCI layouts retain every index, manifest, config, layer, SBOM and
provenance blob. Their actual selected registry object is the sole outer-layout
descriptor, often an inner image/attestation index. Neither a Docker image ID nor
the outer layout's JSON hash is substituted for that digest. The OCI manifest
subject and index annotation both bind each
attestation to the runtime manifest; BuildKit's inner SPDX/SLSA statements may
have empty subject arrays while those hashed graph links remain exact.
The driver accepts the pinned builder's SLSA v1 local-Dockerfile shape and
checks the invocation revision label, nested `vcs:revision` hint, local
context names and any Git material naming this repository against C. It does
not accept an ungrounded v0.2 schema. [Docker documents](https://docs.docker.com/build/metadata/attestations/slsa-definitions/)
local-directory VCS
values as unverified metadata hints and local-context materials as incomplete;
the attestation alone does not prove a complete Git source digest. The clean
source identity checks before and after building, retained payload checks,
reviewed manifest and signature provide the independent source binding.
Two cold builds
compare shipped DP/observer bytes and the entire JVM payload. Tor compares the
source-locked installed package set and publisher bytes, not whole-image digests.
The final binaries/JVM archive come from those retained image payloads. Full
verifier reproducibility tests remain separate required comparisons, including
the cross-host JVM test. Preparation also packages the delivered extension ZIP
twice with separately built, no-cache pinned helpers and records their identical
SHA256 alongside the helper image, recipe, package and source inputs. The
protected job checks the extension ZIP and its input/output record against C.
See [BUILD-DIFFS.md](../BUILD-DIFFS.md).

Retain the action's artifact ID, archive SHA256, run ID and run attempt. The
artifact name includes C and these identities but is not a lookup authority.
Retention is 14 days; a lost or expired artifact requires a new preparation and
new evidence bindings. Promotion never repairs an artifact by rebuilding it.
Git path filtering authenticates checkout files against C; the source manifest
hashes the delivered checkout/archive bytes. This matters for tracked files
whose `.gitattributes` require CRLF on disk and in `git archive`.

## Detached evidence E

Store evidence at `release-evidence/<version>/` in a separate immutable commit E
in the **same repository**. E may follow C. Do not change C or move its tag to
include reports about artifacts produced from C. The driver fetches fixed Git
trees/blobs as data, verifies Git blob identities and SHA256, and never checks
out E or runs its code. Files must be flat, regular, non-executable blobs: at
most 128 files, 8 MiB per report and 64 MiB total.

`index.json` has exactly `schema: 1`, `source`, `version`, `candidate_sha256` and
`files`. `candidate_sha256` hashes the exact retained `candidate.json` bytes.
`files` maps every other evidence filename to its `sha256` and byte `size`.
Duplicate keys, unsafe paths, missing or extra bytes refuse. JSON hashes use the
actual file bytes; generated canonical JSON uses sorted keys, compact separators
and one trailing newline.

Required report metadata:

| File | Required fields |
| --- | --- |
| `T078.json`, `T079.json`, `external-human.json` | `schema: 1`, exact `source`, `status: "PASS"`, `reviewer`, UTC `observed_at`, `report` filename, `independent: true`, boolean `human` (true for external-human) |
| `live.json` | `schema: 1`, exact `source` and `version`, `tracker_sha256`, `observations` |
| `cadence.json`, when candidate has pending named Go suites | `schema: 1`, exact `source`, `artifact_sha256`, `results` |

Every `report` names an included, nonempty full text report, not just a status or
URL. T078/T079 bind C and include the actual final findings/dispositions and
reviewer provenance. The external-human report is a separate Constitution VIII
review; a deployment approval click is not that review. The metadata's reviewer,
independence and human fields are assertions to inspect, not authenticated identities.

`live.json` hashes `specs/001-tor-route/live-e2e/README.md` at C and contains exactly
F1–F5, F7 and R-1–R-8. F6 is the retained actual verifier run. Each observation has
`status: "PASS"`, `scope: "exercised"`, its full `report`, `contract_sha256` of
the exact tracker table row (UTF-8, without newline), and `artifact_sha256`
mapping **all** candidate artifact names to their retained hashes. R-7 additionally
has `coverage` with `routed-ipv6`, `lan`, `vps`, `physical-nic`, `hypervisor`, all
PASS. Include methods, environment/snapshot, complete results, positive controls,
limits and raw-evidence provenance in the reports. Identifiers and hashes alone
do not prove that these observations occurred or covered their contracts.

When `cadence.json` is required, its artifact map is the same complete map. Its
`results` keys are exactly the candidate's pending Go suite names; each value has
`status: "PASS"` and a full `report`. The report must show that the named suite
actually ran, without skipped individual cases, on the identified candidate.
No report supplies commands to execute, credential destinations or skip policy.

## Protected promotion

Before any promotion, a maintainer must configure environment `stargate-release`
with required reviewers, prevent-self-review enabled, administrator bypass
disabled, and exactly one custom deployment policy: **tag `v*`**. The initial
implementation requires at least one configured direct User reviewer; it does
not infer team membership. A read-only API check must be able to observe all
these properties. Missing, inaccessible or omitted fields fail closed, including
the bypass field. Naming an environment in YAML does not configure it. Do not
add a long-lived administrator token to work around an unreadable policy.

Dispatch the same workflow on the same tag with `phase=promote`, C, version,
`evidence_commit=E`, `artifact_id`, `prepare_run_id` and `prepare_run_attempt`.
The read-only `pack` job checks source, tag, successful preparation run, archive
identity/expiry, safe extraction, every retained file, OCI graph, generated
Compose, complete evidence and environment policy. Archive limits are 8 GiB
compressed and 16 GiB extracted; traversal, links, duplicate entries and special
files are refused. The job publishes the exact pack hash and required approval
comment in its summary before the protected job starts.
Remote source checks resolve `refs/tags/<version>` (including annotated tags)
to C at pack construction, before the first registry push, before draft
creation and before publication. GitHub's generic commit lookup accepts a
same-named branch, so it is not used as proof that the remote tag exists.

The reviewer must inspect C, the complete retained artifact and full E report
bodies, establish actual reviewer/report provenance and substantive coverage,
and approve **that pack** with the exact generated comment. The comment names
pack SHA256, C, E, artifact ID and preparation run/attempt. Neither the invoking
actor nor triggering actor may approve. Report JSON cannot authorize promotion.

The protected job independently reconstructs the pack, rechecks policy and
approval history, and compares the approved hash. GHCR uses a short-lived
`GITHUB_TOKEN` with packages/write; Cosign separately obtains GitHub OIDC with
id-token/write. Contents/write is used only for the final GitHub Release. The
token is not put in command arguments or persisted beyond the job's private
temporary Docker credential directory.

Crane copies the already-validated OCI descriptor graph without rebuilding or
reindexing. Cosign signs and verifies the exact registry digests and final
manifest with the expected repository, tag, source SHA, workflow path, dispatch
event and `https://token.actions.githubusercontent.com` issuer. The source-owned
Cosign v3 signing-config file names only Fulcio and one Rekor service, with a
validity end matching the reviewed root's freshness cutoff. The protected job
writes it under its private temporary directory; it does not let an automatically
refreshed signing configuration choose service URLs. A real keyless signing
check remains necessary before claiming end-to-end compatibility.

Only after digest/signature checks does the driver stage a draft release,
upload and hash-check every asset, then publish it. A failed upload may leave
immutable registry blobs, signatures or an unpublished draft. It does not
publish a final manifest or advance a latest channel. Any existing version
release/draft refuses; the read-only pack checks published releases, while
protected promotion verifies push access and queries GraphQL for the exact-tag
release (including drafts) and REST for the published release before its first
push and again before creating a draft. Presence, API errors, incomplete
responses or disagreement refuse. This avoids a draft moving between numbered
release pages, but neither exact-tag read reserves the version. The workflow
serializes target-version promotion runs; authorized human/API release writers
must coordinate with that promotion protocol. A privileged out-of-band edit
can still race a check, draft creation or publication. Tokenless preparation
may retain candidate bytes for a version that later refuses, but has no
publication authority. A maintainer must reconcile an abandoned draft before
retrying, including a create request whose result was lost. A lost publication
response likewise requires manual inspection of the owned release ID and its
assets before any new action; the driver does not retry POST or PATCH
automatically. Cross-repository uploads are not atomic, and concurrent
administrator/tag changes remain outside transactional guarantees. No remote
workflow, runner, tag, protection setting or publication
is performed merely by implementing or testing this workflow.

[GitHub's release API](https://docs.github.com/en/rest/releases/releases#create-a-release)
may reject `GITHUB_TOKEN` with 404 or 403 when the tagged
commit changes `.github/workflows/` relative to the current default branch;
that token cannot acquire the needed Workflows write permission. Before its
first push and again before draft creation, promotion resolves the exact
source and current default commits through GitHub and requires their
`.github/workflows` Git-tree identities to match. The commits themselves may
differ, including when evidence E follows C. Missing or malformed tree data
refuses. A default-branch change after the second check can still make GitHub
reject a write; the driver stops and requires manual reconciliation rather
than selecting a broader credential. A live push-capable token check remains
outstanding.

The signed `release.json` inventories every published asset. Those assets
include the complete retained OCI graphs, source archive, verifier log,
reproducibility record, Tor package report, extension input/output record,
build logs and full detached evidence E. The protected job validates the
retained candidate against its source and image payloads before transforming
the OCI directories and logs into publication archives.

## Trust selection and expiry

The source-owned Sigstore selection records root 15, targets 14, snapshot 166,
timestamp 805 and the target hash/length. The 2026-10-11 audit checked threshold
continuity from the HTTPS-selected historical root 5, current role signatures,
version/hash/length binding and metadata expiry. HTTPS bootstrap trust is an
explicit assumption; this is not a custom production TUF updater or independent
initial root authentication. Cosign performs artifact crypto, certificate,
transparency-log and signing-time validity checks.

For **new promotion**, the selected metadata's earliest freshness cutoff is
2026-10-18T01:48:18Z. At or after that instant, promotion refuses until a reviewed
source update selects fresh authenticated metadata. Evidence, environment
variables and CLI arguments cannot extend it. Preparation may still build bytes;
it cannot turn stale trust selection into publication authority.

Existing artifact installation does not expire at that cutoff: its signature's
trusted signing time and Cosign verification govern validity. An offline static
root cannot discover later compromise, revocation or rotation. Operators need
reviewed trust/tool updates; no background updater, automatic repin, custom
cryptography or insecure verification bypass is provided.

## Installing released Local artifacts

Use a clean Git checkout of the exact source C and existing version tag; this
includes the installer, source Compose, host policy, input pins and verifier.
The shipped `source.tar` is complete audit material, not a scripts-only installer
and not a substitute for the checkout's Git identity checks. Download
`release.json`, `release.sigstore.json` and `compose.json` into a data directory.
Verify the release's source/tag out of band before running its source code.

From that checkout, explicitly acquire the source-pinned verifier/parser tools:

```sh
python3 scripts/release.py install-tools --purpose install
scripts/stargate init --release-dir /absolute/path/to/release-data
```

Tool retrieval is separate and operator-invoked. `init` itself does not download
or execute code from the release directory. It checks actual source bytes and
Git executable modes, HEAD/tag and clean state, then verifies the signed manifest
and exact generated Compose before changing installer state. Signature inputs
and validated Compose are privately snapshotted so later mutations of the input
directory do not change what the installer uses. The ordinary mandatory host
confinement, volume/key preservation and authenticated observer readiness remain
in force. Startup uses `--no-build`; default `init` keeps source-build behavior.
Compose/image/key-helper overrides conflict with release mode and are refused.

Fixtures use recording tools and bounded transport data. Their green result
does not establish actual apt/keyring acceptance, Compose/Buildx/OCI/Cosign
interoperability, configured remote protection, live acceptance or publication.
