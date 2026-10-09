# T213 Tor 0.4.9.14 package promotion evidence

## Candidate and decision

This records the manual promotion from Tor Project Bookworm package
`0.4.9.13-1~d12.bookworm+1` to
`0.4.9.14-1~d12.bookworm+1`. T212's cold T162 attempt retrieved genuine
upstream metadata but failed closed when the old package was absent; the former
pool URL returned 404. The Tor Project's [2026-10-08 announcement](https://forum.torproject.org/t/security-release-0-4-9-14/22241)
calls 0.4.9.14 a security release and recommends updating. It withholds
issue-level details for at least a week, so this evidence does not attribute
particular fixes or claim that the selected package has no defects.

## Authenticated source inputs

Inputs were freshly retrieved from the official sources on 2026-10-09 between
06:02:07 and 06:03:02 UTC, then independently checked before any Tor version
pin edit. The official sources were:

- Key: `https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc`
- Signed index: `https://deb.torproject.org/torproject.org/dists/bookworm/InRelease`
- Architecture indexes:
  `https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-amd64/Packages`
  and `https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-arm64/Packages`
- Package pool files:
  `https://deb.torproject.org/torproject.org/pool/main/t/tor/tor_0.4.9.14-1~d12.bookworm+1_amd64.deb`
  and `https://deb.torproject.org/torproject.org/pool/main/t/tor/tor_0.4.9.14-1~d12.bookworm+1_arm64.deb`

The freshly fetched key contained exactly one primary key with the already-
pinned fingerprint `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`. GnuPG's key record
reported no revoked/expired/disabled status. `gpgv` exited 0 and reported
exactly one `VALIDSIG` for the freshly fetched InRelease, signed by subkey
`2265EB4CB2BF88D900AE8D1B74A941BA219EC810` under that pinned primary. At the
06:04:13 UTC observation, the signed Release date (2026-10-08 02:49:12 UTC) was
before current time and its Valid-Until (2026-11-17 02:49:12 UTC) was in the
future. InRelease is 2,819 bytes, SHA-256
`1d11ca86ef5a6d5fa5f8bc432f652f5eb29bdc63f41a1cb34e74b8c55e006a51`.

Both architecture Packages indexes were hashed and their file hashes and
sizes matched the entries in this same authenticated InRelease. The package
rows in each index named exactly version `0.4.9.14-1~d12.bookworm+1`, and the
downloaded files matched the corresponding row's byte size and SHA-256:

| Architecture | Packages size | Packages SHA-256 | Artifact size | Artifact SHA-256 |
|---|---:|---|---:|---|
| amd64 | 6797 | `ab76f7f2a4044c12081b869dcac14168f7f762709c930bad13ae2cbe5e4bfcfa` | 2100568 | `dfc862fec4100422bf62e18b25278b769662701c9c081f992b51c9d9024976c4` |
| arm64 | 6764 | `9ce5cb181938ae402601c8551d7b0954e5139dad28bec54ce0cc3cc9e7cc5d7a` | 2013456 | `f079056fe7db6708ee83981de6c08f8a983b56ccd23f7798ddd14573390907ff` |

The retained raw inputs, HTTP response headers and machine-readable audit are
under ignored `.scratch/tmp/T213/fresh-input-20261009-v1/`. Its
`fresh-audit.json` SHA-256 is
`032c88fab7ef6a1d83828206730b12315abf29c18db3ecb757cfbbcf9aebb6ad`; it binds
the exact URLs, observation time, tool identities, key/signature status,
Release validity window, index hashes, package paths and artifact hashes.
Tool identities were GnuPG/gpgv 2.4.4, curl 8.5.0, Python 3.12.3 and dpkg-deb
1.22.6. The InRelease and key bytes happened to match the immediately preceding
Oct 8 retrieval, but were fetched again over HTTPS on Oct 9; the Packages indexes
and both package files were also freshly fetched and matched the signed rows.
The build's existing runtime checks still enforce the pinned fingerprint,
one-primary-key rule, live signed repository metadata, current key validity and
revocation behavior, and content hashes. No key, source, freshness,
dependency-source or download policy was relaxed.

## Tests-first contract evidence

The fresh T213 baseline was `efcc7b7841957c18382294af0bf06e113e89268b`. The
staged contract-only expectation change has red snapshot SHA-256
`9660759415aa16cb4810815ad76addd1cd07d05ca3fee2d0d2a0f46715cdcbef`; running
`bash tests/contract/security-decisions/tor_package_integrity_test.sh` exited 1
against the still-pinned `.13` source and reported that `.14` was not selected
and that the installer argument remained `.13`. After the scoped Dockerfile and
both architecture pin rows changed, the identical command exited 0, covering
the existing same-version substitution, missing-pin, failed-download,
unsupported-architecture, and hostile dependency-source controls. The green
snapshot is recorded in the `green.snapshot_sha256` field of the linked
machine-readable red/green record,
`specs/001-tor-route/evidence/T213-tests-first.json`. Neither result replaces
the complete canonical verify or independent implementation review.

## Build and runtime evidence

The native amd64 build used the qualified VPS executor with `--no-cache` and a
900-second build limit. The build action exited 0 after 519.5 seconds with no
timeout or disk-guard failure. It produced the retained OCI archive
`.scratch/tmp/T213/b-a10c8011a71fafa33444681d2634d0c8/executor.oci.tar` (36,150,784
bytes, SHA-256
`8e6ed13d3d8e602c94c2a2276120db05b55b95af04f53e2a9723007b9f5db200`). Its
single runtime manifest is linux/amd64, manifest SHA-256
`53906ff92d490b40d090a28919f55bef660f7f4aefaee5b2a417ab3fe2bf8526`, and
config/image ID `sha256:8fd35b64e195369cfc161e76f4284b13dea01fa6c48300fc4fb6dc85ab01c9d0`.
All ten compressed layer hashes and uncompressed DiffIDs were verified against
the OCI archive.

The retained execution evidence binds that archive to the reviewed candidate
inputs. `.scratch/tmp/T213/preflight.json` records the 9,366-entry
`.scratch/tmp/T213/executor-build-context-manifest-v2.json` by SHA-256
`c4929f306c7176314c795b166090d6aed41448ed4031092fe735e561f5cefde6`, the
build Dockerfile by SHA-256
`b51d5e4d4d4367334cfff3d7919c1fa37eb01563ba24e709ae3176b676c9d511`, and the
frozen invocation by SHA-256
`9f3cb8fe53eb1acca0f103837297003e94b9478f7f5d3ea03c3037b51c1c3679`. The
recipe Dockerfile is byte-identical to `sidecars/tor/Dockerfile` (same
14,293 bytes and SHA-256 above). I compared each local file input from its
`COPY` instructions against both the context manifest and current candidate;
the listed SHA-256 values matched, with no missing path or mode mismatch:

| Dockerfile `COPY` input | SHA-256 |
|---|---|
| `data-plane/go.mod` | `337273804a13c626aa771ac9f5b7109abcf4b7331c6a02e245d7f35fb74922e3` |
| `data-plane/go.sum` | `7e722510ed61309d3b1ff1406360d36a59946511302369ae2dcb0a54b840f7b6` |
| `proto/go.mod` | `f26082ffac33dda2f697d427a95158badc42f993734163161e3d721a6d23ce94` |
| `proto/go.sum` | `6495263da3b90ba578d32e0f74a85ff3871df0129b9f2214fd7c2934309d324f` |
| `data-plane/cmd/tor-health-publisher/main.go` | `1a04a63c7586968fa83fc62d159ccf514afccf013a1b44bad5e4616c2e3c82fb` |
| `data-plane/cmd/tor-health-publisher/main_test.go` | `4f323383a7f6cd60cae09877050ac1459c598661222338547a5f892f3100d669` |
| `data-plane/internal/torhealth/health.go` | `560acaa326329bdf34c0b3e7623055528324bda87e07870d10e7197d094352e9` |
| `data-plane/internal/torhealth/health_test.go` | `7b401ae60ef945fe5987c5fcdb9e6b23f1eeac2d7fdbe53b9dbb93ef3780b3c0` |
| `sidecars/tor/verify-closure.sh` | `c645a4a06a6216f3082ff1bf16aca0fa9eb8c0ea5b2fcecbc9bb2d0fdf8de312` |
| `sidecars/tor/package-closure.lock` | `cd8614f66091d5f1103592241dd0048d1d7a038727af9a17fdac2795867ad268` |
| `sidecars/tor/apt-key.fingerprint` | `d0bb6e7a6bc0d3bf61aa62d087e6dadb22146b6814d12002e217ff89a3a60d96` |
| `sidecars/tor/install-tor.sh` | `e39be643d26c70b15b076a8ce9ed57cc378b75df03261edc251c1dadecfc9805` |
| `sidecars/tor/tor-packages.sha256` | `e30885b6c902768512a1d39ef41a1c09330434442243c6d1519caae75feaaeef` |
| `sidecars/tor/torrc` | `9f127c2c51019b10a7272ea8cb3a389ef55eab057c4ca1bed5b2b02f8ab51924` |
| `sidecars/tor/entrypoint.sh` | `da980dd833926ed26ca30a37c791b295e6086d9f4c1bcb9ac3fcb97884fe2e65` |

The execution join is reviewable from the retained receipts. The preflight is
5,185 bytes, SHA-256
`d87ef5747e77a1fd3a59b5bf0c6ca5b978968ace6b47b65037969bff989a6f9b`; it
binds the context manifest, Dockerfile, frozen invocation, and the same
pre-existing qualified executor inputs before effects began. Buildx was
`0.30.1` (`docker-buildx` SHA-256
`912118a5a65bf2f13dd7c2e5912857c50f43842bf4ec0f4378bcb28af66aaac3`); its
recorded builder inspection reports BuildKit `v0.32.2`, remote driver, OCI
worker, and linux/amd64 support. The caller receipt is 191,284 bytes, SHA-256
`d0ae959ce73144124c26a948bf7b54873ce9302fbfea1e4a8d9e1280dba491ac`; its
final build action is:

```text
/usr/bin/docker buildx build --builder t212buildera10c8011a71fafa33444681d2634d0c8 --progress plain --no-cache --file .scratch/tmp/T213/recipe-v3/Dockerfile --output type=oci,dest=.scratch/tmp/T213/b-a10c8011a71fafa33444681d2634d0c8/executor.oci.tar .scratch/tmp/T213/executor-build-context-v1
exit=0; elapsed=519.497s; action limit=900s
```

The output receipt is 247 bytes, SHA-256
`b7b673e4706fba4d916a71d4251d6c48d8b55d91861f665b2db6aeb457b612ae`; it
records the archive path, 36,150,784 bytes and SHA-256 above. The full manifest,
execution receipts and build log remain in ignored scratch; this compact extract
allows reviewers to check the source-to-archive linkage without copying or
replaying those large artifacts.

The first composite build caller exited 1 during teardown, after the successful
build and archive creation. The copied one-use teardown helper still named the
old T212 unit and evidence directory; it therefore failed its exact-unit
cleanup check and final sentinel assertion. The independent outer stop had
already killed the owned builder and observed the T213 cgroup reach
`populated 0` with no remaining owned tasks. A T213-only helper then stopped only
`t212quala10c8011a71fafa33444681d2634d0c8.slice`. Its receipts show the unit
inactive/dead, its cgroup absent, no owned processes or Docker containers, and
identical foreign container, mount, namespace and Docker-service sentinels.
The original outer failure remains preserved; the build is not recorded as a
green composite caller. A root read-only post-action audit checked the helper
source and receipts. No VM, emulation, broad prune, or image deletion was used.
Details and receipts remain under
`.scratch/tmp/T213/b-a10c8011a71fafa33444681d2634d0c8/` and
`.scratch/tmp/T213/cleanup-v1/`.

The authenticated OCI archive was converted offline with the already-qualified
generic importer and loaded once under the unique local tag
`t213-tor:a10c8011a71fafa33444681d2634d0c8`; no production tag was changed.
Docker reported the exact config/image ID above, linux/amd64, and the same ten
ordered DiffIDs. The image and source archive remain retained. Import receipts
and the compatible archive are under `.scratch/tmp/T213/import-v1/`.

A first no-network observation harness attempt created a uniquely labelled
container but failed its pre-start identity assertion because Docker records
the supplied tag in `Config.Image` and the config digest separately in
`.Image`. It did not start the container or collect runtime measurements. The
exact created container was removed by ID after read-only identity
verification; its cgroup and process were absent afterward and foreign host
sentinels were unchanged. That failed attempt and its targeted cleanup receipts
remain under `.scratch/tmp/T213/runtime-observation-v1/`.

A corrected, separately audited observation ran once with `--network none`,
read-only root filesystem, all capabilities dropped, no-new-privileges, and
the image's non-root `tor` user (UID 5103). It reported `tor`
`0.4.9.14-1~d12.bookworm+1` for amd64 and `Tor version 0.4.9.14.`. All 96
installed amd64 package name/version/architecture triples exactly matched the
96 amd64 identities in `package-closure.lock` (zero missing or unexpected);
the image's `/etc/tor/torrc` SHA-256 matched the source file. The owned
observation container was removed; its cgroup was absent with no host process
members, both cleanup receipts had empty failure lists, and before/after
container IDs, mountinfo, namespaces and Docker-service state were identical.
Raw output and receipts remain under `.scratch/tmp/T213/runtime-observation-v2/`.

The wrapper's cleanup-only process overwrote the main `receipt.json` action
ledger with its final absent-container inspection. The saved container output,
registry, closure comparison, cgroup check, empty cleanup receipt, host-client
reap proof and equal before/after sentinels remain available, but this report
does not claim a complete runtime-call ledger. The first build-wrapper failure
and first runtime-harness failure are retained and are not relabelled as passes.

Hermetic contracts passed: `tests/contract/security-decisions/tor_package_integrity_test.sh`
(including both architecture pins and its rejection/source-isolation controls),
`tor_build_inputs_test.sh`, `tor_entry_test.sh`, and `cd tests/contract && go
test -count=1 ./torrc` (static torrc invariants, rendered-byte match and
no-bridges tests; Docker-tagged integration tests were not run). T213 makes no
arm64 build/runtime, Tor network availability, circuit behavior, integrated
route readiness or T212/T202 closure claim. The upstream Bookworm index remains
mutable; if a later release removes this version, a fresh build still fails
closed pending another manual promotion.
