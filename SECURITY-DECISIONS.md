<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SECURITY-DECISIONS.md

Append-only log of **accepted-finding rationales** and **supply-chain trust
decisions** for Stargate. This file is the durable, human-auditable record
that AGENTS.md, CONTRIBUTING.md §"Review escalations", and THREAT-MODEL.md
§871/§1173 already cite as the canonical home for these decisions.

**Append discipline (binding on every future PR that edits this file):**

- **Ordering.** Dated decision entries are kept in **reverse-chronological
  order (newest first)**, directly below this preamble — a new entry is
  inserted at the top of the dated-decisions region, NOT appended below
  older ones. The "Reserved: adversarial-review findings" section is pinned
  at the **absolute bottom** of the file and is the only non-dated section;
  dated entries never go below it.
- An entry is **never deleted**, and **an entry's body text is immutable once committed**.
  Any change (correction, softening, expansion, or retraction) MUST land as a
  new dated superseding entry with a `Superseded by:` back-link
  from the original, NEVER as an in-place edit of the original body. This
  binds reviewers: a PR that edits a dated entry's body in place (rather than
  superseding) MUST be rejected, even if every contract test stays green.
  When a decision is superseded, the superseding entry adds a
  `Superseded by:` line pointing to the new entry; the original text stays
  verbatim so the audit trail is intact. (Constitution VI — the audit trail's
  integrity against silent weakening cannot rest on the contract tests alone,
  because the tests assert keyword presence + artifact cross-consistency, not
  prose integrity.)
- Every Blocker/Major review or `stargate-redteam`/`stargate-perf` finding
  that is **accepted** (mitigated, risk-accepted, or deferred-with-rationale)
  gets an entry here in the same PR that accepts it (CONTRIBUTING.md §398).
- Factual claims that reference build artifacts (fingerprints, digests) MUST
  match the artifact exactly; the contract tests under
  `tests/contract/security-decisions/` cross-check the load-bearing ones and
  fail the gate on drift.
- This file documents *decisions and their rationale*; it is not a
  duplicate of THREAT-MODEL.md (the model) or the contract tests (the
  enforcement). Where a decision rests on a threat-model row, cite the row.

---

## 2026-10-11 — Validate BuildKit provenance fields, not incidental text (T081 review round 8)

**Accepted Major finding and mitigation.** The OCI inspector previously
accepted a SLSA predicate whenever C appeared anywhere in its JSON. A label
or note could contain C while the invocation identified another revision.
The inspector now accepts the pinned builder's observed SLSA v1 shape only:
BuildKit build type, local Dockerfile frontend and context, exact invocation
revision label and nested `vcs:revision`, and no conflicting own-repository
Git dependency or BuildKit VCS metadata. The v0.2 synthetic fixture was not
grounded against the pinned builder and is no longer accepted. The native
retained minimal OCI v1 sample passes; wrong/missing structured values refuse.

**Scope of evidence.** Docker documents local-context VCS fields as unverified
hints and local-directory materials as incomplete. This check detects
contradictions within retained provenance; it does not certify an independent
Git source digest. The clean source-identity checks around preparation,
retained payload comparison and signed manifest remain the source-C binding
(THREAT-MODEL §3.5; Constitution IV/VI).

## 2026-10-11 — Require the remote version tag namespace (T081 review round 8)

**Accepted Major finding and mitigation.** GitHub `GET /commits/{name}` accepts
branches as well as tags. A same-named branch at C could satisfy the four
remote source checks after the version tag was deleted, allowing promotion to
push and publish against a missing tag. Each phase now fetches
`GET /git/ref/tags/{version}` and resolves lightweight or bounded annotated
tag objects to the reviewed source C. Missing, malformed, changed or
over-nested tag refs refuse before the next promotion phase. Local workflow
identity and source checks remain separate (THREAT-MODEL §3.5; Constitution IV).

**Residual trust.** The authenticated GitHub API and its reported ref/object
graph remain trusted. A privileged actor can move or remove the tag after a
check; the driver rechecks before registry push, draft creation and publish,
but cannot make these phases one transaction. No live release was attempted.

## 2026-10-11 — Query exact-tag release identity during protected promotion (T081 review round 7)

**Accepted Major finding and mitigation.** The round-5 offset-page scan could
miss a target draft when another release before it was deleted between page
requests, even with consistent Link headers and an empty final page. Promotion
now verifies the canonical repository and push-capable token, then uses
GraphQL `Repository.release(tagName:)` to observe the exact tag, including a
draft, and REST `GET /releases/tags/{tag}` to observe a published release.
It performs both lookups before the first registry push and again before draft
creation. Any present target, GraphQL error, incomplete reply, failed access
or REST result other than explicit absence refuses. The returned draft ID must
be newly created by this run and match the requested tag before asset upload;
no existing draft is adopted or overwritten (THREAT-MODEL §3.5).
GitHub's current release API can also reject `GITHUB_TOKEN` when C changes
`.github/workflows` relative to the default branch; that token cannot acquire
Workflows write permission. Both guards therefore resolve C and the current
default commit and compare their `.github/workflows` Git-tree identities.
Missing, malformed, truncated or mismatched tree data refuses before registry
push or draft creation. Equality of whole commits is not required.

**Residual trust.** These are observations, not a version lock. The workflow
serializes target-version promotion runs, and authorized human/API writers
must coordinate with it. Privileged out-of-band edits can race either lookup
or the owned draft's publication. An abandoned draft or an uncertain create or
publish response requires manual reconciliation; the driver does not retry
those writes automatically. A real push-capable token compatibility check is
still outstanding; local transport fixtures test the response parser and
decision path, not GitHub's live authorization behavior. A default-branch
change after the second workflow-tree check can still cause GitHub to refuse
release creation or publication.

## 2026-10-11 — Require an empty draft-visible release-list sentinel (T081 review round 5)

Superseded by: [the round-7 exact-tag decision](#2026-10-11--query-exact-tag-release-identity-during-protected-promotion-t081-review-round-7).

**Accepted Major finding and mitigation.** Per-page Link termination could
still stop on a short page without Link, even after an earlier page claimed a
later `last` page. A first-only Link could also end a nonempty list. Protected
promotion now constructs consecutive page requests itself and treats Link only
as a persistent consistency claim. It requires actual HTTP 200 and a well-formed
empty page beyond every claimed existing page; nonempty pages always continue.
Changing last-page claims, a premature empty page, malformed/foreign Link, API
error or partial status refuses. A hard cap refuses at 1,000 returned rows,
before a possibly misleading empty page beyond GitHub's accessible result window.
The same check runs before the first registry push and before draft creation
(THREAT-MODEL §3.5; `scripts/release.py` and release transport fixtures).

**Residual trust.** A successful scan assumes GitHub supplies a complete,
contiguous draft-visible list below the cap and returns HTTP 200 `[]` beyond
its end; the latter is observed behavior rather than a published guarantee.
Concurrent release insertion, deletion, retagging or visibility changes can
move a draft to an already-read page. The second scan narrows, but cannot
eliminate, that window; it is neither a snapshot nor a version reservation.

## 2026-10-11 — Exhaust release-list pagination before protected promotion (T081 review round 4)

Superseded by: [the round-5 empty-sentinel decision](#2026-10-11--require-an-empty-draft-visible-release-list-sentinel-t081-review-round-5).

**Accepted Major finding and mitigation.** The draft-aware list guard previously
validated only `next` links; a `last=2` link without `next` could falsely mark
page 1 complete. It also accepted a full 100-item page without a Link header
without checking whether page 2 existed. Both paths could miss a later draft and
permit registry pushes and signing. The guard now validates every supplied Link
relation and rejects contradictory, foreign, malformed, duplicate or out-of-bound
pages. Any full page without a `next` relation triggers one bounded next-page
query; a terminal Link that conceals data is a contradiction and refuses. An
empty follow-up page completes the traversal, while a later draft or unreadable
page refuses before mutation. An ordinary short or empty single page remains valid
(THREAT-MODEL §3.5; `scripts/release.py` and release transport fixtures).

**Phase correction.** Tokenless preparation has no release API check or publication
authority. The read-only approval pack checks published releases; protected
promotion is the authoritative draft-visible reuse gate. No token is injected
into preparation's build/tool subprocess environment.

## 2026-10-11 — Draft-aware version reuse refusal in protected promotion (T081 review round 3)

Superseded by: [the round-7 exact-tag decision](#2026-10-11--query-exact-tag-release-identity-during-protected-promotion-t081-review-round-7).

**Accepted Major finding and mitigation.** `GET /releases/tags/{tag}` reports
published releases, so its 404 did not establish that a failed upload had left
no unpublished draft. A retry could push images and sign again before learning
that the version was claimed. The read-only approval-pack phase retains that
early published-release check; tokenless preparation has no release API check.
Before the first registry push, protected promotion now verifies its
token's push access for the canonical repository and traverses the bounded
draft-visible release list, validating response shape and pagination links. It
repeats the check immediately before creating the draft. A matching published
release or draft, missing push proof, inaccessible list or incomplete traversal
refuses. GitHub's list-releases API documents draft visibility for principals
with push access; its pagination API documents Link headers. The driver now
constructs consecutive page requests itself (round-5 decision). The transport
fixtures cover a hidden draft after a published
lookup 404, a later-page draft and failed visibility (THREAT-MODEL §3.5).

**Residual trust.** The API's authenticated permission report and release list
remain trusted. Concurrent administrator changes and cross-repository atomicity
are outside the existing guarantee; retries do not delete or reuse drafts.

## 2026-10-11 — Refuse redirected Docker daemons before local init policy (T081 review round 2)

**Accepted Major finding and mitigation.** Source and signed-release init imposed
host-boundary policy on the invoking machine, but Docker could select a remote
daemon through DOCKER_HOST, DOCKER_CONTEXT or a stored currentContext. The local
policy would then protect the wrong host while Compose started the data plane
elsewhere. This violated the local deployment claim under Constitution III and
THREAT-MODEL §3.5. The common init preflight now requires Docker's effective
selected context to be `default`, its resolved daemon endpoint to be the local
rootful `/var/run/docker.sock` or `/run/docker.sock`, and its security options to
exclude rootless. Missing, malformed, redirected or alternate-socket responses
refuse before host policy, volumes, keys or containers mutate. Both init modes use
the same guard; the T081 release init fixture tests refusals in each mode, and the
existing T106 count-probe fixture retains its original fail-closed assertion.

**Residual trust.** The local Docker CLI, daemon and socket identity remain trusted;
a compromised local host can lie about daemon state or change host policy. This
does not confer host isolation on remote Docker deployments. See THREAT-MODEL §3.1
and §3.5 and `scripts/subcommands/init`.

## 2026-10-11 — Immutable source and separately promoted release artifacts (T081)

**Supersession.** The historical 2026-07-04 Tor rationale's instruction to append
final image digests to this file/source Compose at tag time is superseded by this
entry. Historical bodies remain unchanged. Reviewed source contains base/build
input pins; final four runtime registry digests belong to generated release Compose
and a signed manifest. No final artifact identity can rewrite its reviewed source
or move the selected existing version tag (Constitution IV/VI; THREAT-MODEL §3.5).

Preparation retains exact OCI bytes, source, input identities and reproducibility
records with read-only grants. Promotion retrieves the same immutable artifact ID,
validates detached evidence from fixed paths at a same-repository commit as data,
and requires the protected stargate-release environment's non-self approval of the
exact pack. Registry GITHUB_TOKEN authority and OIDC signing authority are distinct.
A deployment click cannot replace the external-human review required by VIII.

Only the verified full-source init path may admit generated Compose; it retains the
mandatory local host policy and authenticated readiness and never builds release
images. Failed validation refuses before provisioning. Failed cross-repository
uploads can leave immutable remote objects; publishing the verified signed manifest
is the commit point. Uploads are not transactionally atomic across repositories.

This is a reviewed-source contract and implementation target, not a published-release,
apt/signature-validation or live-acceptance claim. The source-owned Sigstore selection
records the audited metadata chain and a conservative new-promotion freshness cutoff;
the HTTPS bootstrap assumption and offline revocation limits remain explicit.
Actual input/tool compatibility, final reviews and all required live evidence,
including R-7, remain required. See docs/releasing.md for the trust boundaries.

## 2026-10-09 — Promote Tor 0.4.9.14 after the pinned package left the index (T213)

**Decision and authorization.** T212's cold T162 build fetched genuine Tor
InRelease and amd64 Packages metadata, then failed closed because the pinned
0.4.9.13 package was no longer listed. The old pool artifact returned 404.
Under the maintainer-authorized T213 prerequisite, select
`0.4.9.14-1~d12.bookworm+1` from the same official Bookworm repository. The Tor
Project's [2026-10-08 security release announcement](https://forum.torproject.org/t/security-release-0-4-9-14/22241)
recommends updating and withholds issue-level details for at least a week; this
decision makes no claim about specific fixes or absence of defects. It
supersedes only T177's selected package identity. It does not deploy or publish
an image, and T212/T202 integrated route qualification remains pending.

**Authenticated inputs (resolved 2026-10-09 06:04 UTC).** The freshly fetched
official key contained exactly one primary key matching the existing pin
`A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`; its GnuPG status was not revoked,
expired or disabled. `gpgv` validated the newly fetched Bookworm InRelease with
one `VALIDSIG` from subkey `2265EB4CB2BF88D900AE8D1B74A941BA219EC810` under
that primary fingerprint. The signed Release is dated 2026-10-08 02:49:12 UTC
and valid until 2026-11-17 02:49:12 UTC. Its SHA-256 is
`1d11ca86ef5a6d5fa5f8bc432f652f5eb29bdc63f41a1cb34e74b8c55e006a51`.
The amd64 Packages index SHA-256 is
`ab76f7f2a4044c12081b869dcac14168f7f762709c930bad13ae2cbe5e4bfcfa`; the arm64
index SHA-256 is
`9ce5cb181938ae402601c8551d7b0954e5139dad28bec54ce0cc3cc9e7cc5d7a`. Both
indexes and artifact identities were checked against that same signed
metadata. Downloaded artifacts matched its exact size and SHA-256 rows:

| Architecture | Package filename | Size | SHA-256 |
|---|---|---:|---|
| amd64 | `tor_0.4.9.14-1~d12.bookworm+1_amd64.deb` | 2100568 | `dfc862fec4100422bf62e18b25278b769662701c9c081f992b51c9d9024976c4` |
| arm64 | `tor_0.4.9.14-1~d12.bookworm+1_arm64.deb` | 2013456 | `f079056fe7db6708ee83981de6c08f8a983b56ccd23f7798ddd14573390907ff` |

**Native measurement outcome.** The bounded `--no-cache` amd64 BuildKit action
exited 0 and emitted a retained OCI archive, but the initial composite caller
exited 1 because its copied cleanup helper still referenced T212's prior unit.
A separately reviewed T213-only cleanup stopped that exact empty unit and
verified foreign-resource sentinels. The archive was imported offline under a
unique local inspection tag; one corrected no-network observation checked the
installed Tor version, amd64 package identities and baked torrc. These results,
the retained initial cleanup failure, first pre-start runtime-harness failure,
and action-ledger limitation are detailed in `reviews/T213/README.md`. They are
not integrated route qualification and do not make the initial composite caller
a pass.

The native amd64 image build and installed-package checks, including their
limits, are recorded in `reviews/T213/README.md`. Authenticated arm64 package
bytes do not establish arm64 build or runtime behavior. Package identity does
not establish Tor network availability, unchanged circuit behavior or
integrated route readiness. The Tor index remains mutable and may drop this
version with a later release; a clean build then fails closed until another
manual reviewed promotion. No archive, cache bypass or validity waiver is
added. The T160 checked local-file installer, signing-key and revocation checks,
Debian-only dependency source, no-download installation, and all other pins
remain unchanged.

## 2026-10-02 — Tor observer image identity is a checked local build, not published provenance (T191)

**Context.** T138 ("Packaging and identity") required the observer's "immutable digest and
verified provenance before deployment" and said that "a mutable tag or unverified local build
cannot close this ticket". T164 deferred image provenance and shipped a narrower model, recorded
in `specs/001-tor-route/contracts/foundation-boundaries.md` ("T138/T164 observer boundary"):
`scripts/stargate init` builds the observer from `sidecars/tor-observer/Dockerfile` on a
digest-pinned Go builder (Go verifies downloaded modules against `go.sum`), labels the image with
init's SHA-256 over the module files, the observer's `main.go` and that Dockerfile, re-reads the
label and recomputes the hash after the build, and deploys the resulting local `sha256:` image ID
through the generated env file. The shipped env example holds an all-zero placeholder that cannot
resolve to an image, and Compose has no `build:` for the observer. The 2026-09-29 redteam
reconciliation (gap G3) found no decision record reconciling the two texts; the 2026-10-01
reconciliation closes finding 20260727-001 with this residue.

**Decision.** For source-built Local deployments, the only path init supports until T081's
release Compose exists, the observer's deployed identity is the image ID init's own build
returned: a content-addressed local image ID, recorded with init's hash of the checkout's observer
source files. This narrows T138's "verified provenance" requirement for that path; it does not
meet it in the Principle IV sense. The label records which checkout bytes init asked the daemon to
build. init has no reviewed reference value to compare them with, so the source is only as
reviewed as the operator's checkout. It is not a signature, an attestation, or a claim that an
independently published binary was verified. init writes only the ID its own build returned into
the env file and never writes a mutable tag. init refuses to run when `STARGATE_OBSERVER_IMAGE`
is set in its environment, which Compose interpolation would otherwise let override the env file.

**Residual risk.** The binding trusts the operator's checkout, Docker daemon and builder
(including any remote BuildKit worker selected by `BUILDX_BUILDER`), the pinned Go builder image
and the module bytes fixed by `go.sum`. A compromised build host can produce a correct label over
different bytes. init's refusal branches (label mismatch, non-digest result) are implemented but
have no negative-control test; the positive path was measured in T165's live run. Observer binary
and image reproducibility are neither claimed nor measured here. Published-artifact provenance
(registry digest, signature, SBOM) and Constitution VI release reproducibility evidence for the
observer belong to T081, whose acceptance names the observer image alongside the DP, CP and Tor
images. Direct Compose starts outside init remain unsupported (2026-09-20 T162 entry).
(THREAT-MODEL §3.1 trusted parties, §5.9, §8.6.)

**Owner and re-evaluation.** Owner: the maintainer; T081 for published provenance and
reproducibility. Re-evaluate when T081's release Compose lands, when the observer's source set,
Dockerfile or init's build path changes, or when a LAN/VPS profile deploys the observer.

**Evidence.** `scripts/subcommands/init` (`observer_source_hash`, `build_observer_image`, the
`STARGATE_OBSERVER_IMAGE` refusal); `tests/contract/stargate-cli/t162_enforcement_test.sh`; `tests/contract/stargate-cli/init_test.sh`
(static literals); `tests/contract/compose/local_compose_test.sh` (rendered Compose: a `sha256:`
reference and no `build:`); `specs/001-tor-route/analysis/T165-observer-evidence.md` (deployed
label matched the tested source hash); `contracts/foundation-boundaries.md` T138/T164 paragraph.

---

## 2026-10-02 — Erratum: the Tor repository drops the pinned build with each new bookworm build (T191)

**Finding.** The 2026-07-04 Tor sidecar entry (T099, "Rotation" bullet) describes the loss of
an old `.deb` from `deb.torproject.org` as a residual the Tor Project "could" cause. It happens
whenever the repository publishes a new bookworm `tor` build, in practice each Tor stable release; T124's fresh-volume build already failed this way when 0.4.9.13 replaced 0.4.9.12 (2026-09-26 T177 entry). The repository's bookworm index lists only the current Tor build (fetched
2026-10-02: exactly one `tor` version, `0.4.9.13-1~d12.bookworm+1`, the one pinned in
`sidecars/tor/tor-packages.sha256`), so the pinned version leaves the index when the next
release ships. The 2026-09-29 redteam falsification pass confirmed this upstream behaviour.

**Decision (wording only; mechanism unchanged).** A clean build still fetches Tor only by its
pinned `=version` through `sidecars/tor/install-tor.sh` (`apt-get download tor=<version>`) and
then checks the reviewed content pin. After each new bookworm `tor` build that fetch fails and the
build stops before any image exists (fail closed). Recovery is the reviewed promotion T160 and
T177 already used: verify the new signed metadata and package bytes, then update the Dockerfile version, `tor-packages.sha256` and the Tor rows of `package-closure.lock` together (2026-09-12 T160 update procedure; 2026-09-30 T184 entry). Plan for this on each new bookworm build, not as a rare event. Running containers are unaffected, but a clean build fails, including first-time `stargate init` and any re-init without the cached Tor layer; init stops the DP before rebuilding, so such a re-init leaves the data plane, and so the Tor route, stopped (fail closed); the control plane, Tor and observer keep running. A reviewed candidate's Tor image cannot be rebuilt from clean after the next upstream build, so reproducibility and release builds (T081) must run before it or follow a promotion.

**Owner and re-evaluation.** Owner: the maintainer (Tor promotions). Re-evaluate if the Tor Project offers a retained or snapshotted index, or Stargate keeps a reviewed local copy of the pinned package.

**Supersession.** This supersedes only the clause of the T099 "Rotation" bullet that the Tor Project "could remove an old `.deb`"; T160 already superseded that sentence's immutability claim. The rest of that entry and its other supersessions stay in force.

---

## 2026-09-30 — Refuse rolled-back Debian snapshot metadata for the Tor image (T184)

**Finding.** Redteam `20260929-002-tor-closure-index-rollback` (area 3 M1) survived
falsification. `snapshot.debian.org` InRelease files for 20260714, 20251201 and 20240101
carry no `Valid-Until`, and apt's `Max-ValidTime` defaults to 0. Over the plain-HTTP
snapshot transport an on-path attacker can therefore serve an older, genuinely signed
bookworm index at the pinned URL. The `=version` pins floor that replay only at Debian
12.12 for the runtime stage: the 20251201 index still carries `ca-certificates
20230311+deb12u1` and `netcat-openbsd 1.219-1` but `libssl3 3.0.17-1~deb12u2`
instead of `3.0.20-1~deb12u2`. The A-versus-B reproducibility test passed such a
consistent attacker. A signature authenticates origin, not freshness.

**Decision.** Pin the reviewed metadata itself and the resulting closure, both committed in
`sidecars/tor/package-closure.lock` (Constitution IV: refuse rolled-back metadata; failed
verification leaves nothing built):

- **InRelease hash.** The snapshot run `20260714T082229Z` InRelease (bookworm 12.15, Date
  2026-07-11 10:16:37 UTC) has SHA-256
  `77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa`.
  `sidecars/tor/verify-closure.sh inrelease` checks the stored file after every
  `apt-get update` in both stages, before anything is installed from it; the runtime
  stage re-checks after its second update because that update re-fetches the snapshot
  index. apt has already verified the signature, and the InRelease binds every Packages
  index and therefore every `.deb` hash. A missing InRelease (forced `Release` fallback)
  also fails.
- **Closure lock.** After the last install, `verify-closure.sh closure` requires every
  installed package's name, version, package architecture and archive SHA-256 (as recorded
  by the enabled, signature-verified indexes, or `base` when no index carries it) to equal
  the image architecture's lock rows exactly; an identity two indexes record with different
  hashes never matches. The Tor row equals `tor-packages.sha256`.

The amd64 rows (96 packages) were printed inside a real amd64 build. No arm64 builder
exists on the grounding host, so the arm64 rows were resolved by bookworm APT 2.6.1 from the
same pinned indexes and the arm64 base image's dpkg status, mirroring the build's install
steps; the same procedure reproduced the real amd64 rows exactly. The arm64 rows are not
build-confirmed; a wrong row fails the arm64 build closed rather than admitting drift.

**Supersession.** This supersedes the T099 text in the 2026-07-04 entry that the snapshot
pin freezes the closure ("every build selects the SAME bytes") and that the missing
`Valid-Until` needs no handling. Those statements held only without an on-path attacker.
The rest of that entry, including its residual risks, stays in force; the closure still
rides Debian's archive signing key, and the lock makes it auditable, not trustworthy.

**Evidence and limits.** `tests/reproducibility/tor_sidecar_manifest_test.sh` compares
two cold builds with the committed lock and runs two negative controls: a tampered lock row,
and a loopback proxy that serves the genuine 12.15 index to stage 1 and the signed 12.12
index under the pinned URL to stage 2. Before this change the replay built an image with
`libssl3 3.0.17-1~deb12u2`; after it, both controls fail at the named T184 check
(`specs/001-tor-route/evidence/T184-tests-first.json`). The structural gate is
`tests/contract/security-decisions/tor_build_inputs_test.sh` (B7). Refresh stays a
manual, reviewed promotion: bump the snapshot run, every `=version` pin, the InRelease hash
and the lock rows together, from `verify-closure.sh print` output and grounded metadata;
never accept a changed row merely because a build failed. The Tor repository index remains
mutable and freshness-bounded by its own `Valid-Until`; the Tor package stays content-pinned
(T160/T177). Base image identity remains its digest. Final image digests remain T081's.

---

## 2026-09-26 — Promote Tor 0.4.9.13 verified security package (T177)

**Decision and authorization.** The maintainer authorized a separate update after T124's
fresh-volume build failed because the Tor Project's Bookworm index no longer selected the
reviewed 0.4.9.12 package. Tor's [2026-09-23 security announcement](https://forum.torproject.org/t/security-release-0-4-9-13/22178)
describes high-severity issues affecting clients, onion services and relays and recommends
prompt updating. Select `0.4.9.13-1~d12.bookworm+1` from the same official repository.
The former 0.4.9.12 selection remains a historical decision; this entry supersedes only its
selected package identity. This source/image preparation does not deploy or publish an image.
T124 still requires a separate fresh-volume integrated READY run and review.

**Authenticated inputs (resolved 2026-09-26).** The fetched Tor repository key had exactly
one primary key, matching the existing fingerprint
`A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`. `gpgv` validated the Bookworm
[InRelease](https://deb.torproject.org/torproject.org/dists/bookworm/InRelease) signature
from subkey `2265EB4CB2BF88D900AE8D1B74A941BA219EC810`. Signed metadata is dated
2026-09-25 11:28:01 UTC and valid until 2026-11-04 11:28:01 UTC. The actual
[amd64](https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-amd64/Packages)
and [arm64](https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-arm64/Packages)
Packages files matched their SHA-256 and size in that signed Release. Downloaded package
bytes matched the corresponding authenticated Packages rows and the new independent lock:

| Architecture | Package filename | SHA-256 |
|---|---|---|
| amd64 | `tor_0.4.9.13-1~d12.bookworm+1_amd64.deb` | `6dd261277646e309cb9571861722862fe646c76bb5f0b7b72ee1e6ab2fd1c01a` |
| arm64 | `tor_0.4.9.13-1~d12.bookworm+1_arm64.deb` | `db443c92ed416a1f06f8a7c8f538642a641d6c96c6a98402134f9467369d0ff9` |

The T160 checked local-file installer, package-substitution controls, dependency-source
isolation, Debian snapshot and signing-key policy remain in force. Native amd64 build
verification and exact candidate review belong to `reviews/T177/README.md`; downloaded
arm64 bytes do not establish arm64 runtime behavior. Tor-network availability and
integrated route readiness remain T124's unfulfilled live acceptance until measured.

---

## 2026-09-22 — Enforce certificate validity and bounded IPC authority (T148)

**Supersedes:** the 2026-07-12 T095 certificate-validity rationale, for expiry enforcement,
renewal and established-channel authority. T156 Principle II requires possession of the private
key, the currently authorized pin and a valid certificate; matching keys alone are insufficient.
This reconciles the implementation with that policy, not a weakening or finding waiver.

**Decision:** wire-auth §2.4 specifies exact local-clock validity checks with only the existing
five-minute issuance backdate, automatic in-memory renewal within the final 24 hours or before
use after an idle outage, and independently enforced IPC connection lifetimes of at most
60 seconds. Established channels have bounded residual authority after pin replacement or expiry;
new handshakes have no expiry grace. Routing under retained valid auth state survives IPC loss.

Go uses its full/resumed verification hook and bounded transport credentials. Java uses separate
JDK TLS contexts per engine because grpc-netty constructs SslHandler directly, bypassing Netty's
context-associated resumption controller. Disabling Java session reuse preserves authentication
without relying on a callback that production does not invoke. Synthetic and real Go/Java UDS
checks are listed in THREAT-MODEL §5.13 and reviews/T148/README.md.

**Corrected rationale:** a certificate alone cannot impersonate its holder; possession of the
currently pinned private key CAN impersonate the peer without restarting the legitimate plane.
A stolen key can mint new valid certificates. Certificate expiry does not bound key compromise;
operator key rotation remains necessary. No automated keypair rotation is introduced. Host clock
integrity and process scheduling remain timing preconditions; no instantaneous revocation or
new live-network anonymity evidence is claimed.

---

## 2026-09-21 — Retire T125 embedded-resolver acceptance on the measured Local boundary (T163)

**Decision and authority.** Retire only residual (b), the embedded-DNS side
channel accepted in the 2026-09-07 T125 entry below, for the measured replacement
Local deployment. T162 already withdrew the wildcard/no-masquerade posture in
the 2026-09-20 entry. T168 supplies mandatory process confinement, T170 repairs
enforcing-profile signal/lifecycle compatibility, and T163 supplies cumulative
packet evidence. This does not accept the former channel under Constitution III
or change any other historical acceptance.

After receiving the measured result and proposed replacement wording, the
maintainer replied **"vm is approved"** on 2026-09-21. T163's contract now accepts
an independently booted Linux VM or bare-metal host, with the actual deployment
namespaces and every capture, per-family, restart and failure/recovery control
retained. The alternative was waiting for separate physical hardware. This is
an evidence-scope refinement, not permission to change DP/CP traffic or bypass
confinement. Physical-NIC, hypervisor and untested kernel/architecture behavior
remain outside the VM result; the constitution and external release review
obligations remain binding.

**Measured closure.** The DP has no Docker embedded-resolver attachment. On the
Ubuntu Linux 6.8.0-139-generic amd64 guest (Landlock ABI 4), the complete
`T163-20260921-024737` run passed all 29 capture-validity controls with zero
kernel drops. Unrestricted TCP/UDP/DNS controls were visible; DP probes emitted
no marked traffic and could not use the working loopback forwarder/resolver.
The owner-loss, Compose restart, re-init and mandatory-confinement failure/recovery
phases passed. T170 also verified enforcing-profile startup and host lifecycle
signals. The [measured report](specs/001-tor-route/analysis/T163-packet-evidence.md)
records source/image/capture identities, controls, commands and failed attempts;
THREAT-MODEL §3.1/§5.8 retains the precise scope.

**Remaining obligations.** No routed IPv6, physical hardware, browser/Tor-circuit
or release result follows. IPv6 received explicit admission refusal and loopback
resolver controls/denial. T164/T165 own sanitized observer closure; T155 owns
integration, and the release gates remain. Re-evaluate this measured closure
when the DP confinement, namespace/fabric topology, enforcement profile or
supported kernel/architecture changes; T155 consumes that evidence.

---

## 2026-09-20 — Withdraw T125 wildcard/no-masquerade local posture (T162)

**Decision.** The T125 `STARGATE_IN_CONTAINER` wildcard exception and the
`stargate-host` no-masquerade attachment are withdrawn as a local-profile
security posture. T134 demonstrated that this shape did not establish the
Constitution III application-plane egress boundary; T156's binding text
already forbids inheriting it. No constitutional amendment or acceptance of
the residual DNS/UDP path is implied. The T162 replacement is a strict
host-loopback DP listener, Tor-only bridge egress, separate SOCKS/observer
Unix fabrics, UID-scoped silent host OUTPUT drops on both IP families, and
AppArmor mediation of the host abstract-socket channel. T164 must implement
the sanitized observer before CP Tor health is restored; T163 must establish
production-namespace packet evidence. Until those gates pass this record is
a withdrawal and implementation direction, not a conformance claim.

**Why host state is trusted.** Docker Compose alone cannot impose the
owner-match rule on host-networked DP packets. The installer stops a running
DP, installs/verifies the host rule/profile, then starts it. The host admin
and Docker daemon can still flush or bypass this policy; THREAT-MODEL §3.1
names that trust explicitly. Direct Compose/Docker starts without the
installer are unsupported, not an alternate secure path. The rule uses
no LOG target because packet-specific denial records would violate
Constitution III's aggregate-only audit limit. See T162's acceptance 6,
T134 A.9/A.11/A.12, and the local Compose contract.

---

## 2026-09-12 — Tor 0.4.9.12 security promotion and exact package content pins (T160)

**Decision and authorization.** The maintainer explicitly requests the Tor security upgrade
announced on 2026-09-08. Select the Tor Project's Bookworm package
`0.4.9.12-1~d12.bookworm+1`. Fold pending T140 into T160 and perform this urgent dependency
repair before T139. Constitution IV/VII/VIII, independent review and existing foundation
closure obligations remain binding. This is a reviewed-source/image preparation task;
no production restart, image publication or automatic update is authorized here. Required live
upgrade validation is tracked separately in T161 and blocks deployment/release promotion,
T155 and final reviews; preparing this candidate does not satisfy that gate.

**Security relevance.** Upstream describes memory-safety and client-availability fixes and a
Conflux stream-isolation correction (TROVE-2026-040). Existing T058 observations must be
rechecked against the new binary; they do not authorize weaker isolation rules.
Sources: [official announcement](https://forum.torproject.org/t/security-release-0-4-9-12/22096)
and [tagged release notes](https://gitlab.torproject.org/tpo/core/tor/-/raw/tor-0.4.9.12/ReleaseNotes).

**Authenticated inputs (resolved 2026-09-12).** The primary signing fingerprint remains
`A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`; the fetched key contains exactly one primary key.
The Bookworm InRelease signature verifies under that key, using signing subkey
`2265EB4CB2BF88D900AE8D1B74A941BA219EC810`. Signed metadata is dated 2026-09-11 14:20:58 UTC,
valid until 2026-10-21 14:20:58 UTC. Both uncompressed Packages indexes match the SHA256 and
size in that signed Release. Actual downloaded package bytes match these authenticated hashes:

| Architecture | Package filename | SHA256 |
|---|---|---|
| amd64 | `tor_0.4.9.12-1~d12.bookworm+1_amd64.deb` | `e9fdce1afa50faa36ae1b6df80c004eff24668c245d4667d00e5bdb3d115365c` |
| arm64 | `tor_0.4.9.12-1~d12.bookworm+1_arm64.deb` | `5b305c8fd942d536bcda9644b716dfb49a424da6dc854aa59116557987144f59` |

Metadata: [Bookworm InRelease](https://deb.torproject.org/torproject.org/dists/bookworm/InRelease),
[amd64 Packages](https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-amd64/Packages),
[arm64 Packages](https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-arm64/Packages).
Packages are under the repository's `pool/main/t/tor/` path. Grounding records and actual
build/test/review outcomes are retained with T160 delivery evidence, including unavailable checks.

**Enforcement and supersession.** `sidecars/tor/tor-packages.sha256` is an independent,
reviewed content lock. `install-tor.sh` downloads the exact version through authenticated apt
metadata into a private cache without unpacking it, checks the selected architecture's
immutable hash and installs that exact local file with package downloads disabled. After checking
Tor, dependencies are downloaded into the same cache with only the pinned Debian snapshot source
enabled; both dependency resolution and final installation exclude all source-parts directories.
The Tor repository cannot supply replacement libraries even when it offers a higher version or
different bytes under the same version. Real offline APT fixtures reproduce both source-selection
cases. A Tor-only hash check with both repositories enabled retained this inherited gap; lowering
repository priority alone does not isolate same-version download sources. No dependency versions
are refreshed by this repair. Installation cannot fetch replacements.
A real APT build demonstrated that naming a local file alone could still trigger a repository
download. The `--no-download` install phase prevents that bypass; missing cache data fails rather
than being silently held back (`--ignore-missing` is not used). See the
[Bookworm apt-get contract](https://manpages.debian.org/bookworm/apt/apt-get.8.en.html).
A missing pin, unsupported architecture, failed download or changed package bytes prevents
installation. Download scratch state is removed on exit and the build helper/pin files are
removed from the final runtime filesystem. The existing base digest, Debian snapshot,
Debian package versions, upstream key, non-root identity and torrc are preserved.

This supersedes the Tor version/hash selection and the claimed Tor-package immutability in
the 2026-07-04 entry: a named version plus a hash from a mutable signed index authenticates the
current publisher's choice, but does not prevent that publisher from replacing same-version
bytes. The independent content check mitigates finding
`20260727-002-tor-deb-hash-never-verified` (T140, folded into T160). Closure requires
the independent T160 reviews and delivered fix commit. The original entry remains
historical; its other trust decisions and residual risks are retained.

**Update procedure and limits.** A later promotion must verify new signed metadata and actual
package bytes, then update the selected version and both architecture locks together, with
negative controls, builds and applicable protocol checks. Do not accept a new hash merely
because a build failed or upstream removed an old artifact. Signature trust, content identity,
package-manifest reproducibility and final-image reproducibility are distinct. Native amd64
execution does not establish arm64 runtime behavior; authenticated arm64 bytes establish only
selection/integrity. Final release artifact identities remain T081's responsibility. This entry
does not assert that the remaining topology, observer, browser or isolation repairs are closed
(THREAT-MODEL §2.6/§5.8; T155).

Superseded by: [T177 Tor security promotion](#2026-09-26--promote-tor-04913-verified-security-package-t177), for the selected Tor package version/hash only.

---

## 2026-09-07 — Erratum: FR citation corrected in the SC-002 amendment entry (record-only supersession, T061 round-1 review follow-up)

The 2026-09-07 entry "SC-002 corpus measurement mechanism corrected"
(below) cites **FR-007** for its bearer-token clause ("bearer token
verified at the data plane, never re-sent upstream"). That citation is
wrong: FR-007 pins the SOCKS5 **username**-only passthrough and is silent
on the password. The bearer-token facts are pinned by **FR-002** (the
extension sets the inbound SOCKS5 password to the device's bearer token)
and **FR-006** (the data plane verifies it, HMAC-SHA-256 + install-time
pepper), with `data-plane/internal/forward/tor.go` `dialUpstream` as the
code anchor: the DP dials the sidecar with the inbound UNAME verbatim and
an empty password (PLEN=0) — "auth-layer material that is never re-sent
upstream". The finding, the decision, and the security analysis of the
superseded entry are unchanged; only the citation is corrected. Spotted by
the T061 round-1 codereview (Minor, record-only); filed as a supersession
because this log's entries are immutable once committed.

## 2026-09-07 — FR-010 bind policy amended to a container-boundary reading; host loopback-only exposure unchanged (T125 live-run finding, ESCALATE → amend-spec, user-approved)

Superseded by: [T163 measured Local embedded-resolver closure](#2026-09-21--retire-t125-embedded-resolver-acceptance-on-the-measured-local-boundary-t163)
for residual (b) only; the original record below is preserved.

**Finding (accepted, Major — the local profile's core path was
architecturally unreachable as speced).** FR-010's literal reading (the
data plane binds `127.0.0.1` only) combined with FR-005's host-published
`127.0.0.1:8881` and Docker's publishing semantics produced a dead port:
docker delivers a published port to the container's **eth0**, so a
container-**loopback** listener is unreachable — from the host AND from
compose neighbours. Probed live 2026-09-07 (docker 29.1.3): with the DP
booted clean and its own log showing `startup listener=127.0.0.1:8881`,
host `CONNECT 127.0.0.1:8881` → connection refused;
`nc -z stargate-dp 8881` from the tor container → refused. Masked until
the first-ever full-stack bring-up (T122 discovery chain); the hermetic
gates never exercise docker networking. THREAT-MODEL §3.1's
"proxy ports bind to 127.0.0.1" row is about HOST-facing exposure, which
is exactly what survives this amendment.

**Finding, round 2 (live).** The first cut of this decision moved the
bind to the wildcard but kept the DP on internal networks only — and
Docker **silently discards published ports on internal:true networks**
(the container config carried `127.0.0.1:8881` while
`NetworkSettings.Ports` was null; host CONNECT still refused). Caught by
the T059 live run minutes after landing round 1. Fix: a dedicated
`stargate-host` bridge network (NOT internal, `enable_ip_masquerade:
"false"`), attached to the DP only — publish-capable, egress-dead
(probed: `HOST-TCP-OK` through the publish; `nc 1.1.1.1 80` from the net
blocked as designed).

**Decision.** FR-010 is amended to a boundary reading: the loopback-only
HOST guarantee is carried by (a) the host-side publish
`127.0.0.1:8881:8881` over the dedicated no-masquerade `stargate-host`
attachment (long-form publish, structural-gated; masquerade off) and (b)
the container network namespace (T094b's `internal: true` split) — not by
the in-container bind address. Inside compose (attested by
`STARGATE_IN_CONTAINER=1`, set only in `docker-compose.local.yml`) the
DP binds the container-wide address `0.0.0.0:8881`. A SPECIFIC
non-loopback interface literal stays refused in both modes (the listener
may be container-wide, never pointed at a shared interface); bare-metal
runs keep the original loopback-only contract
(`bind.CheckListener`, `data-plane/internal/bind`).

**Why the relaxation is bounded.** The wildcard is only honoured when the
compose file attests the container boundary; that env travels with the
version-controlled compose file, and whoever can set the DP's environment
is already inside the deployment (THREAT-MODEL §3.1 assumes local
execution is game-over). The host-facing surface an external adversary
meets is unchanged: loopback publish over the no-masquerade host
attachment (no IP egress from it), transport nets internal-only.

**Residual risk accepted.** (a) A misconfigured compose file that dropped
the `127.0.0.1:` prefix from the publish would now expose the DP wildcard
listener beyond loopback; mitigated by the structural compose contract
pinning the long-form loopback publish (M1), and unchanged for
bare-metal runs. (b) The embedded DNS resolver on the non-internal
`stargate-host` attachment still forwards external names, so a
COMPROMISED data plane retains a DNS side-channel even with IP egress
blocked (no masquerade); accepted because a compromised DP already holds
in-flight request bytes and the token-verifier set — the runtime
no-DNS-leak behaviour for non-compromised operation stays gated by T034.
(c) LAN/VPS profiles (real non-loopback interfaces) remain out of scope
and still require their tunnel sidecars.

**Enforcement.** `bind.CheckListener` unit rows (loopback/wildcard/specific
IP per mode, `data-plane/internal/bind/check_test.go`), the compose
environment block + ports comment (`compose/docker-compose.local.yml`),
and the full-vertical runtime gates (T059/T033 live runs) that motivated
the fix.

---

## 2026-09-07 — SC-002 corpus measurement mechanism corrected; isolation property unchanged (T061 grounding, ESCALATE → amend-spec, user-approved)

**Finding (accepted, Major — measurement unimplementable as speced).**
SC-002's original mechanism — 100 sequential CONNECTs addressed TO the
100 synthetic-corpus `.onion` strings, asserting ≥95 distinct circuit
IDs — cannot run on the pinned sidecar, established by pre-
implementation probes against `compose up tor` (T058's harness, T062
helper, in-container SOCKS5 dial). Two independent facts: (1) every
corpus address is rejected at parse — tor logs `ed25519 group order
scalarmult failed` / `Service address [scrubbed] has bad pubkey` /
`Invalid onion hostname [scrubbed]; rejecting` and answers `REP=0x01`
with no stream and no circuit. The corpus passes T063's A5 (checksums,
shape, distinctness) because A5 validates the checksum over whatever
key bytes exist; it does not require the embedded 32-byte key to be a
valid Ed25519 public point, and the corpus's random keys are not.
(2) The reachability premise fails independent of the corpus: an
address built from a fresh, valid Ed25519 keypair (unpublished — no
descriptor exists) is accepted at parse, but its stream lingers at
`SENTCONNECT 0` with no per-connection circuit for the whole
observation window; tor attaches an HS client stream to a circuit only
after the descriptor arrives. Positive control (the spec-pinned
reference onion over the same dial path) attached and carried the
`SOCKS_USERNAME` tag normally, so the observation harness is not the
variable. Spec §Assumptions' "reachability is not required … only that
the Tor sidecar attempts distinct circuits" is therefore false on this
image: the sidecar does not attempt.

**Decision.** User-approved amend-spec (2026-09-07): SC-002 and the
Assumptions bullet are rewritten so the corpus strings serve as the
per-CONNECT SOCKS5 username — the isolation key the extension sends in
production (FR-007) — while each CONNECT targets the spec-pinned
reachable reference onion; the assertion (≥95 distinct
`SOCKS_USERNAME`-tagged circuit IDs across the 100 streams, read via
FR-012's control port) is unchanged. US2's acceptance scenarios are
untouched: they describe user-visible behavior and remain true; the
amendment corrects only the harness measurement mechanism.

**Security analysis (no weakening).** The property under measurement is
the same and is now actually measured (previously it was unmeasurable —
zero verification): 100 distinct first-party labels from the committed
corpus → ≥95 distinct sidecar-assigned circuits. The username is the
isolation axis the shipped config enforces: `IsolateSOCKSAuth` keys
circuits on the SOCKS auth identity, the baked torrc carries no
destination-based isolation directive, and the 2026-09-07 T058 entry
(below) pins the behavioral pair — distinct identities isolate,
identical identities share — on this exact tor build. Destination was
therefore never an isolation input, so removing it from the measurement
removes no guard. FR-007 (bearer token verified at the data plane,
never re-sent upstream), FR-012, the static torrc gates (T029/T030/
T031/T032), T058/T058a, and the through-the-data-plane tests (T059/
T060) are all unchanged by this amendment. The corpus's Ed25519-invalid
keys are harmless in its two remaining roles (isolation-key strings
here; forbidden substrings in T064's leak corpus); should any future
consumer use them as addresses, regenerate the corpus with valid
keypairs (remediation optional, none filed today).

**Superseded by:** §"2026-09-07 — Erratum: FR citation corrected in the SC-002 amendment entry (record-only supersession, T061 round-1 review follow-up)" (citation-only correction; findings, decision, and security analysis stand).

## 2026-09-07 — `IsolateSOCKSAuth` behavioral redundancy on tor 0.4.9; contract-sheet sensitivity claim corrected (T058 review round 1, ESCALATE → amend-spec)

**Finding (accepted, Major).** `contracts/torrc.md`
§"isolate_socks_auth_effect_test.go" claimed the US2 contract test is a
gate on the loaded `torrc` such that "if `IsolateSOCKSAuth` were silently
dropped, this test fails immediately". T058's mutation battery — run by
the implementer and independently reproduced by the codereview agent —
proved that false on the pinned tor `0.4.9.11-1~d12.bookworm+1`: with the
directive removed from `sidecars/tor/torrc` (mutation verified
in-container — the baked `/etc/tor/torrc` bytes AND `GETCONF SocksPort`
both show it absent), `TestIsolateSOCKSAuthDistinctCircuits` still passes
with the two distinct-identity streams on distinct circuits; the control
experiment (two CONNECTs, identical identity) shows them sharing one
circuit. I.e. on this Tor version, distinct SOCKS username/password
identities isolate regardless of the flag, and identical identities share
regardless — the directive is behaviorally redundant for this probe
family, so the test cannot detect its own namesake's removal.

**Decision.** (a) The contract sheet is amended to state what the test
actually gates — the US2 acceptance scenario 1 *behavioral* property
(distinct first-party auth identities → distinct circuits on the real
sidecar; a Tor upgrade that merges them fails the digest-bump PR's live
run) — and to attribute dropped-directive detection to the static gates:
invariant #1 via T029's byte-match and T030's invariants, plus T032's
live GETCONF. (b) The `IsolateSOCKSAuth` directive itself STAYS in the
baked `torrc` unchanged (invariant #1 remains a privacy invariant per the
contract's own change procedure): it is the spec-pinned declaration of
the isolation intent, costs nothing, defends against a future Tor
release changing isolation defaults (where it becomes load-bearing
again), and removing it would require a fresh entry here per
contracts/torrc.md §"When this contract changes" item 4.

**Residual risk.** A reader of the older contract prose could over-trust
the behavioral test's sensitivity; mitigated by this entry, the amended
contract sheet, and the ticket's §Notes record (T058). The behavioral
property itself remains gated and verified live (T058's test, docker
cadence). None additional.

---

## 2026-09-02 — `alpine:3.20` contract-test image digest pin (T107)

**Decision.** The two stargate-cli contract-test artifacts pull their
helper image by digest, never by mutable tag (Principle IV — every
external component digest-pinned; T084's review round 1 carved this out
as the last committed-executable-code tag pulls):

- `tests/contract/stargate-cli/init_docker_test.sh` — `STAT_IMAGE`
  const (all five `docker run` / `docker create` uses flow from it):
  `alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`
- `tests/contract/stargate-cli/fixtures/fixture-compose.yml` — a
  top-level `x-alpine` YAML anchor aliased into all three services, so
  the digest appears exactly once in the file.

**The pin.** `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`
is the multi-arch OCI index digest of `alpine:3.20` (16 child
platform manifests), resolved **registry-direct** (Docker Hub v2 API
`docker-content-digest` header, the same resolution
`docker buildx imagetools inspect alpine:3.20` performs — not from a
local cache) and verified end-to-end by pulling the pinned ref.

**Scope honesty.** This is test-only surface: the images run volume
`stat`/`sha256sum` helpers and trivial fixture services on development
hosts, not any shipped profile. It was still a live Principle IV
deviation in executable code — on any host with a Docker daemon the
mutable tag resolved at pull time with no integrity anchor, and these
helpers reach the mounted repo volume and (in the daemon-backed
assertions) daemon-created containers. The pin closes that.

**Rotation policy.** Manual promotion, review-driven, one PR: resolve
the new digest registry-direct, update the `STAT_IMAGE` const AND the
fixture `x-alpine` anchor AND land a NEW dated superseding entry here
carrying the new digest (dated entry bodies are immutable once
committed — the preamble's supersede-only discipline governs; the
superseding entry adds the `Superseded by:` back-link to this one),
then re-run `tests/contract/stargate-cli/init_docker_test.sh` with a
daemon reachable. Alpinelinux publishes point releases under the same
`3.20` tag, so the tag's digest moves without any Stargate-side action
— the pin holds the tested bytes until this promotion runs.

**Enforcement cross-reference.** No dedicated cross-file contract test
for this pin (T107's files_budget covers only the two test artifacts).
The two refs are held to the same digest by construction — the fixture
services alias the single `x-alpine` anchor, and the script's five
image uses all dereference the single `STAT_IMAGE` const — plus the
review-time whole-tree grep (`alpine:[0-9][^@]`, T084 acceptance-#2
taxonomy), which is what surfaces any divergence or new tag-only
literal. **The daemon-gated suite itself does NOT detect divergence
between the two refs**: it exercises only that each ref is pullable
and functional (services come up on the anchor's ref, assertions stat
with the const's ref), so a partial rotation updating one ref and
forgetting the other would still pass end-to-end. A cheap hermetic
cross-file grep assertion closing that gap is deferred to a follow-up
ticket. The grep now classifies these two files as canonical pins
(T084's acceptance-#2 exclusion of them lapses); its residual hits are
T084's pre-existing excluded classes (SECURITY-DECISIONS illustrative
TCB prose, the `port_exposure_test.go` rotation-procedure comment,
ticket/STATUS prose).

---

## 2026-07-16 — docker-socket-proxy mechanism removed (T094a)

**Supersedes** §"2026-07-06 — docker-socket-proxy `CONTAINERS=1` read
surface (corrective supersession, T019c redteam)" and §"2026-07-04 —
docker-socket-proxy trust rationale (auxiliary container)" below —
**in full, by removal**: the proxy mechanism no longer exists in the
code, so both entries' rationale (property bought, residual trust,
mitigations, exposure surface) is moot for forward-going work. Their
prose is retained verbatim below for the audit trail, each carrying a
`Superseded by:` back-link to this entry.

**Decision.** T094a removed the `docker-socket-proxy` auxiliary
container from the local profile entirely. No service in
`compose/docker-compose.local.yml` mounts `/var/run/docker.sock`
(gated by `tests/contract/compose/local_compose_test.sh` M4 — zero
mounters). The control plane now observes Tor lifecycle through Tor's
own **cookie-authenticated ControlPort** (`tor:9051`, enabled by
`CookieAuthentication 1` + `CookieAuthFileGroupReadable 1`;
`specs/001-tor-route/contracts/torrc.md` invariants #3–#4) over the
compose-internal network, NOT through a Docker Engine observer.

**Why the proxy is unnecessary for routing correctness.** T090 removed
control-plane route-admission gating (the DP no longer waits on a CP
`HEALTHY` event before routing). The proxy existed to let the CP observe
sidecar container lifecycle for that admission gate; with the gate gone,
the proxy's only remaining job was feeding `SidecarMonitor` (T039) its
`STARTED`/`HEALTHY` transitions. Tor's control port reports bootstrap
and health state authoritatively (the Tor Dockerfile's own HEALTHCHECK
already probes `GETINFO status/bootstrap-phase` over cookie auth), so
the control port is a strictly narrower observation surface than a
generic Docker Engine observer — and one that introduces no
host-root-pivot path (Constitution Principle III: no service holds a
`docker.sock` handle).

**Why this is the narrower surface (net privacy improvement).** The
superseded 2026-07-06 entry flagged that the proxy's `CONTAINERS=1` ACL
was section-granular, not path-granular: it granted `GET /archive` over
EVERY container's filesystem — including Tor's entry-guard state under
`/var/lib/tor` (THREAT-MODEL §4.2). Removing the proxy retires that
exfiltration path entirely. The control-port cookie exchange carries
only what `SidecarMonitor` needs (bootstrap/health state), and the
narrow cookie-read volume is constrained (T094a §Analysis "Grounding
decisions") to avoid re-introducing a broad `/var/lib/tor` read.

**What changed in the tree (T094a).**

- Removed `docker-socket-proxy` from `compose/docker-compose.local.yml`
  (service, `/var/run/docker.sock` mount, env lockdown, CP
  `depends_on`); removed `DOCKER_SOCKET_PROXY_IMAGE` from
  `compose/env/local.env.example`.
- Rewrote `tests/contract/compose/local_compose_test.sh` to assert
  exactly three services and ZERO `docker.sock` mounters (M4 inverted
  from "sole-mounter == proxy" to "no mounter at all").
- Removed `tests/contract/sidecar-proxy/lockdown_test.go` (T019c) and
  the `tests/contract/sidecar-proxy/` directory — the proxy it gated no
  longer exists.
- Removed `tests/contract/security-decisions/docker_socket_proxy_entry_
  test.sh` (T017a) and `tests/contract/arch/docker_socket_proxy_section_
  test.sh` (T018) — both hard-asserted the removed entry/§16.1/digest;
  their load-bearing invariants are moot now that the proxy is gone,
  and this superseding entry carries the record.
- Amended `specs/000-architecture/spec.md` §16, `specs/001-tor-route/
  spec.md` FR-012, and `specs/001-tor-route/plan.md` so no governance
  artifact describes a proxy the code lacks (Principle V).

**THREAT-MODEL cross-reference.** THREAT-MODEL.md does not name the
proxy (§5.8 Sidecar compromise and §3.1 Local profile never did); no
threat-model edit was required for the removal. §3.1's "Docker daemon
on the host" trusted-party line is mode-level, not proxy-level, and
stands. The "Docker isolation is not a security sandbox" honest note
for the split/hardening work is T094b's mandate (its acceptance #5),
not T094a's.

**LAN/VPS release-blocker (carried forward, re-scoped).** The cookie-
auth ControlPort observation surface inherits the local-profile scoping
of the mechanism it replaces (THREAT-MODEL §3.1: local code execution
is already game-over). Any future LAN or VPS profile feature spec MUST
revisit how the control plane observes sidecar lifecycle: a non-
localhost profile exposes the CP and DP to remote callers and changes
the compromise-probability calculus for every observation surface (the
DP is the most concerning reacher — it faces internet-supplied input
the CP does not). The chosen surface must be re-evaluated before that
profile's compose file ships.

## 2026-07-15 — Bearer-token verifier: HMAC-SHA-256 + install-time pepper (T092)

**Accepted findings:** sol-review **B5** (Blocker — per-request Argon2id is
an allocation-based denial-of-service path) and **M1** (Major — token
lifecycle state is internally inconsistent). Recorded in
`review/sol-review.md` §B5 and §M1.

**Decision.** Replace the Argon2id bearer-token verifier with
**HMAC-SHA-256 over a dedicated 32-byte install-time pepper** shared by the
control plane and data plane. The candidate's tag is computed once per
request and compared with `crypto/subtle.ConstantTimeCompare` against every
verifier in the current generation (no short-circuit). The pepper never
enters `dp-snapshot.json`, the inter-plane RPC, any log, or any audit
`detail_json`. Full contract in `specs/001-tor-route/data-model.md` §1.

**Why this is the right trade (B5).** A bearer token is a uniformly random
128-bit value. Offline brute-force of a 128-bit secret is infeasible at
*any* verifier speed (the 2^128 space dwarfs any feasible guess rate), so
the slow-KDF property Argon2id provides is worthless for a random token —
Argon2id earns its keep on *low-entropy human passwords*, which bearer
tokens are not. Meanwhile the prior 64 MiB / parallelism-4 Argon2id
allocation was an unbounded memory-DoS vector:
`golang.org/x/crypto/argon2.IDKey` allocates its full `memory` block slice
up front, so 200 concurrent one-token auths allocate ~`200 × 64 MiB =
12.8 GiB`, reachable by any local process via the loopback proxy. HMAC auth
makes per-request allocation O(1) regardless of token-list size N or
concurrent flood size. The B5 finding is falsified by **T079a's extended
design (peak-RSS + unauthenticated-flood bounds, not pool-fill timing
alone)** — pinned as a test by T093 before production implementation
resumes (Principle VII). The retired N ≤ 4 cap is gone: HMAC auth is
O(1) hash work per request regardless of N.

**Why the lifecycle fix (M1).** The prior design had no persistent
generation source (a CP restart re-hashed and pushed generation 1, which
would be stale the moment the DP accepted any generation ≥ 1 and silently
revoke every client), treated `tokens.yaml` I/O failure as revoke-all, and
required `enrolled_devices` inserts to carry a nonexistent device public
key. T092 introduces: (a) a persistent `token_generation` record the CP
reads at start to propose `last + 1`; (b) a `ReloadTokens` reconciliation
handshake — a stale proposal returns `APPLY_STATUS_STALE_GENERATION` plus
the DP's `current_generation`, so the CP retries with `current + 1`;
(c) failure semantics where missing/unreadable/invalid/unparseable input
makes the CP **not** call `ReloadTokens` (the DP keeps last-known and keeps
serving — Principle II), and only a successfully-parsed explicit
`tokens: []` is revoke-all; (d) a dedicated `configured_tokens(label,
verifier, …)` entity for the manual-YAML path, leaving `enrolled_devices`
(device pubkey NOT NULL) for the future dashboard-enrollment feature;
(e) a narrowed memory-erasure claim that covers only the mutable HMAC
input `byte[]`, not SnakeYAML-materialized immutable `String` values the
loader cannot reach.

**Breaking pre-release contract change (no `stargate.v2` bump).** The proto
`TokenHash { hash; salt }` becomes `TokenVerifier { verifier }` (the
per-token `salt` field is dropped — a single shared pepper makes it dead)
and `ReloadTokensResponse` gains `current_generation`. Dropping a field
from a proto3 message is a breaking change. Per the **pre-release
amendment doctrine** established by T091 / T099 (constitution
`.specify/memory/constitution.md` Sync Impact Reports): semver-on-
amendments and the 7-day public comment window become BINDING only at
first public release; the project has shipped no binary and has no public
remote with consumers, so the change is recorded HERE as an amendment NOTE
rather than as a `stargate.v2` bump. The formal governance flow (PR +
comment window) applies to the same change once the repo is public. This is
the same boundary used for the Principle III bullet-3 amendment (T091) and
the Principle VI Tor-reproducibility tier (T099); it is not a new
exception. The proto comment block and `contracts/control-grpc.md`
§"ReloadTokens" carry the amendment NOTE in lock-step.

**Residue / supply-chain decision (the pepper is a new secret).**

- **Ownership / mode.** `/etc/stargate/keys/pepper.key`, generated once by
  `scripts/stargate init` (`openssl rand -bytes 32`), mounted from the
  `stargate-keys` volume, owned by the reading plane's UID, group-readable
  by `stargate-ipc` (GID 5100), mode `0640` — the same ownership/mode
  scheme as the ed25519 inter-plane keypairs in that volume.
- **Threat-model row.** Pepper compromise + a `dp-snapshot.json` leak lets
  an attacker test candidate tokens offline at HMAC speed. Mitigated by
  the 128-bit token entropy: even at billions of HMAC/sec, batch
  brute-force of a 128-bit space is infeasible — the property Argon2id
  was over-engineered to defend (needlessly, for a random token). Recorded
  in `THREAT-MODEL.md` §5.14.
- **Constant-time over the verifier set** is functionally tested in T093;
  adversarial confirmation of the timing side-channel bound is a
  `stargate-redteam` residue (functional tests do not fully capture timing).
- **Backup / export / wipe / rotation.** The pepper MUST be in any operator
  backup of `stargate-keys` (without it every persisted verifier is
  uncomputable and all stored tokens effectively revoke); `export` warns
  the bundle now carries a secret; `wipe` removes it alongside keys and
  state; rotation is operator-initiated (re-pepper → re-HMAC every
  configured token → bump generation). T088 wires provisioning, export,
  wipe, and rotation.

**Downstream artefacts amended in lock-step (acceptance #7):**
`data-model.md` §1 (full contract); `spec.md` FR-006/FR-013/FR-017/FR-018;
`contracts/control-grpc.md` §"ReloadTokens"; `proto/stargate/v1/control.proto`;
`plan.md` Constitution Check rows II/V/VII + Scale/Scope + SC-005 model;
arch §6 (configured_tokens + token_generation) + `V001__init.sql`;
`THREAT-MODEL.md` §5.14. Dependent tickets refined: T020/T020a/T035/T035a/
T041/T044/T046/T079a/T088. T093 pins the contract as tests before T035/
T041/T044/T046 resume.

## 2026-07-12 — Tor `torrc` image-baking contract (T089 static-startup amendment)

**Context.** Review `sol-review.md` B2 found that Compose starts the
`tor` service before `stargate-control`, while the Tor entrypoint reads
its config from the shared `stargate-tor-config` volume
(`sidecars/tor/Dockerfile:120-124`). A control-plane-rendered `torrc`
written later does not make a running Tor reload it, so Tor could start
with the Debian default config (no `IsolateSOCKSAuth`, no `SafeLogging 1`)
or fail because the expected file is absent. The last case is a privacy
failure, not just an availability issue. T089 amends the contract so the
static Tor-only slice bakes the exact safe `torrc` into the image at
build time and does not claim the control plane renders it at boot
(Constitution Principle II — Tor startup must not depend on CP
availability or Compose timing).

**Decision (T089 §Acceptance #1–#2, amending FR-011 / `contracts/torrc.md`
/ `data-model.md` §6 / plan Constitution Check / THREAT-MODEL §4.2).**

- The byte-pinned safe `torrc` from `contracts/torrc.md` §"Rendered
  file" is **baked into the Tor image at build time** (`COPY` into
  `/etc/tor/torrc`, T087) and loaded by the entrypoint at container
  start. The control plane does NOT render `torrc` at boot in this slice.
- `DataDirectory /var/lib/tor` is now **explicit** in the byte template
  (contracts/torrc.md invariant #11, flipped from "NO override"). The
  entrypoint runs `tor -f /etc/tor/torrc` WITHOUT
  `--defaults-torrc /etc/tor/torrc-defaults`, so Debian's defaults file
  (which would set `DataDirectory /var/lib/tor`) is never loaded
  (sol-review B2+M3 / T087). Without the explicit directive Tor falls
  back to its compile-time default `$HOME/.tor` = `/var/lib/tor/.tor`,
  landing the control cookie at `/var/lib/tor/.tor/control_auth_cookie`
  — not the `/var/lib/tor/control_auth_cookie` the healthcheck and
  T062's control-port helper assume. Pinning it makes the cookie path
  deterministic.
- Control-plane-rendered `torrc` (atomic write into `stargate-tor-config`
  by `TorrcRenderer`, T037) is **deferred** to a dynamic-config feature
  (bridges toggle, live reload). T037 is deferred with it
  (`deferred_reason: spec-amend`, `deferred_on: T089`). The
  `stargate-tor-config` volume's CP-RW / Tor-RO role is not used for v1
  boot (data-model.md §6 amended).

**Why accepted for the local profile.** Baking the torrc into the image
is the B2 recommendation and is strictly safer than a CP-rendered torrc
under Compose's `tor`-before-`stargate-control` ordering: it removes the
boot-coupling Principle II forbids and guarantees the privacy directives
(`IsolateSOCKSAuth`, `SafeLogging 1`, `UseBridges 0`, no `Bridge` lines)
are present at Tor's first boot. The cost is that a torrc change now
requires an image rebuild (T087's cold-volume regression test gates the
image `/etc/tor/torrc` == golden), which is the right cadence for a
static slice and is no barrier to the future dynamic-config feature
re-introducing CP rendering behind a Tor-depends-on-CP-health ordering.

**Residue / what changes for dynamic config.** A future feature that
re-introduces control-plane-rendered `torrc` MUST (a) re-open the
ownership decision recorded here, (b) remove the Compose cycle per B2's
recommendation (start CP without Tor, make CP healthy only after an
atomic render, make Tor depend on that health condition) rather than
relying on Compose timing, and (c) supersede this entry with a dated
superseding entry + `Superseded by:` back-link. The `config_render`
detail value in `contracts/control-grpc.md`'s `SidecarEvent` vocabulary
is already reserved for the `CONFIG_RELOADED` event that feature will
emit.

**Enforcement cross-reference.**

- Contract document: `specs/001-tor-route/contracts/torrc.md` §"Rendered
  file" + invariant #11 (amended by T089).
- Byte-for-byte gate: `tests/contract/torrc/render_byte_match_test.go`
  (T029) — `wantTorrc` golden updated in lock-step with the contract
  template; `tests/contract/torrc/invariants_test.go` (T030) Row 11
  flipped to assert `DataDirectory /var/lib/tor` present.
- Image-side gate (T087, not yet landed): cold-volume regression test
  reads `/etc/tor/torrc` out of the image without harness-seeded config
  and asserts it equals the golden; also asserts Docker
  `State.Health.Status == healthy` and the authoritative cookie path.
- Threat model: `THREAT-MODEL.md` §4.2 "Stargate-specific notes" (image-
  baked torrc note added by T089).
- Downstream consumers: T087 (implement the amended image, healthcheck,
  cold-volume test), T037 (deferred), T041 (startup sequence no longer
  renders torrc).

---

## 2026-07-12 — Inter-plane X.509 certificate validity policy (T095 wire-auth contract)

Superseded by: [T148 validity and IPC authority](#2026-09-22--enforce-certificate-validity-and-bounded-ipc-authority-t148), for validity enforcement, renewal, existing-channel deadlines and the private-key impersonation rationale.

**Context.** T095 completed the inter-plane wire contract
(`specs/001-tor-route/contracts/wire-auth.md`) that arch §5.4 had left
underspecified and that review `sol-review.md` M5 flagged as a Major finding
("Inter-plane version/auth claims have no complete wire contract"). The
contract specifies that each plane derives a self-signed X.509 cert from its
on-disk Ed25519 private key at process startup, holds it in memory only, and
re-derives it on every restart. This entry records the accepted policy
decisions around validity and rotation so the residue is operator-visible
per Constitution V.

**Finding (T095 §Analysis residue).** The certificate validity window and
the absence of automated key rotation are operator-visible facts that the
threat model and this log MUST carry — they bound the value of a stolen
in-memory cert and the operator-action cadence for key replacement.

**Accepted policy (T095 §2.2 + §6).**

- `NotBefore = now − 5 min` (negative-skew window for compose-stack clock
  drift), `NotAfter = now + 30 days`. The cert is re-derived on every plane
  restart, so practical lifetime is "until next plane restart, capped at 30
  days".
- Certs are never persisted; the on-disk artefact set stays byte-reproducible
  modulo the keyfiles themselves (Constitution VI).
- Key rotation (replacing `cp.priv`/`cp.pub` / `dp.priv`/`dp.pub` in the
  `stargate-keys` volume) is **operator-manual in v1**. Automated rotation
  (CP-driven key generation + atomic install + plane restart) is explicitly
  out of scope for T095 and for the Tor-route feature; it is a future feature
  with its own threat-model entry.

**Why accepted for the local profile.** THREAT-MODEL §3.1 treats same-host
code execution as game-over; the in-memory cert's 30-day window does not
expand that surface. The pin-on-public-key design (`wire-auth.md` §3) means
a stolen cert without the matching private key is worthless, and a stolen
private key without a plane restart cannot mount a MITM (the peer-pin check
fails on the attacker's key). **The binding residue is key compromise, not
cert compromise**: an attacker who reads a plane's process memory obtains
the long-lived private key (loaded from `*.priv` for handshake signing) and
can impersonate the plane indefinitely — minting fresh, currently-valid
certs from the stolen key — until the operator manually rotates the on-disk
keypair. The 30-day cert-validity window does NOT bound this exposure; a
monthly plane restart does NOT help (the same key is re-loaded). This is no
worse than the §3.1 same-host assumption in the local profile; it is the
operator's keypair-rotation lever (§6.2) that bounds the incident, not the
cert validity window.

**What changes for LAN/VPS.** Under a LAN/VPS profile the inter-plane
channel may cross a network (a future feature, see `wire-auth.md` §4.1 and
§8). The 30-day cert window and the operator-manual rotation cadence MUST
be re-reviewed against a network-positioned adversary at that point; the
current acceptance is local-profile-scoped. A LAN/VPS feature that
introduces TCP transport MUST revisit §4 of `wire-auth.md` (SAN verification
vs pin) and this entry in the same PR.

**Enforcement cross-reference.**

- Contract document: `specs/001-tor-route/contracts/wire-auth.md` (T095).
- Compose-level regression test: `tests/contract/compose/inter_plane_wire_test.sh`
  (T095) gates key-file ownership/mode, peer-plane dial success, out-of-group
  `EACCES`, wrong-key rejection, major mismatch, minor compatibility, no TCP
  transport, and CP-restart survival. Runtime rows self-skip until T038/T045/
  T050 land.
- Threat-model residue: `THREAT-MODEL.md` §5.13.
- Downstream consumers: T038 (CP gRPC server + ReloadTokensClient), T045 (DP
  gRPC server + WatchEvents client), T050 (DP main boot order) — each
  consumes `wire-auth.md` verbatim per T095 §Acceptance #5.

---

## 2026-07-06 — docker-socket-proxy `CONTAINERS=1` read surface (corrective supersession, T019c redteam)

**Superseded by:** §"2026-07-16 — docker-socket-proxy mechanism removed
(T094a)" above — in full, by removal. The prose below is retained
verbatim for the audit trail.

**Corrects (partially supersedes)** the 2026-07-04 entry "docker-socket-proxy
trust rationale (auxiliary container)" below. Scope of the correction: the
characterization of the **read** surface the env-flag filter grants.
Everything else in the 2026-07-04 entry — property bought, residual trust,
exposure surface, `:ro` caveat, mitigations, release-blocker — stands
unchanged.

**Finding (stargate-redteam at T019c, 2026-07-06, major).** The 2026-07-04
entry states the CP "can `GET /events` and `GET /containers/{name}/json`
… and nothing else", and the T019c ticket residue as first drafted narrowed
the `CONTAINERS=1` over-grant to notice-log exposure. Both understate the
granted surface. The proxy's env-flag ACLs are **section- and
method-granular**, not path-granular: `CONTAINERS=1` with `POST=0` allows
**every GET/HEAD under `^(/v[\d.]+)?/containers`**, including:

- `GET /containers/{id}/archive?path=…` — tar-export of any file from ANY
  container's filesystem (e.g. Tor's entry-guard state under `/var/lib/tor`,
  documented sensitive in THREAT-MODEL §4.2);
- `GET /containers/{id}/json` — full inspect (env vars, mounts, network
  config) of every container, not only `tor`;
- `GET /containers/json`, `/top`, `/logs`, `/stats`, `/changes`, `/export`
  and the rest of the read-only containers section.

**Why the local-profile accept still holds.** THREAT-MODEL §3.1: the local
profile assumes same-host code execution is already game-over, and the CP
already mounts the keys volume directly. A CP compromise reading guard state
via `/archive` adds no capability a same-host attacker lacks. The property
the proxy buys — **no write surface, so no host-root pivot** (`POST=0`
denies every non-GET/HEAD verb) — is unaffected and remains runtime-gated
by T019c's `PostSurfaceDenied`.

**What changes for LAN/VPS.** The 2026-07-04 entry's release-blocker
paragraph inherits this correction: under a LAN/VPS profile a CP compromise
is NOT co-located with the host, so "arbitrary container-filesystem read of
every container" (entry-guard state, rendered torrc, CP state DB) is a
materially larger exfiltration surface than "read tor's notice-level
stdout". The mandated LAN/VPS revisit MUST scope against the
section-granular grant, not the two-endpoint shorthand.

**Enforcement cross-reference.** `tests/contract/sidecar-proxy/
lockdown_test.go` (T019c) runtime-gates the deny surface; its
`DenyByDefaultSurface` sub-test was hardened in the same PR to probe an
API-version-prefixed path (`/v1.43/version`) and `HEAD /_ping`, so an
upstream image bump that regresses the version-prefix regex or the method
filter fails the test rather than silently widening the surface (T019c
redteam minor finding, resolved in-code).

## 2026-07-04 — docker-socket-proxy trust rationale (auxiliary container)

**Superseded by:** §"2026-07-16 — docker-socket-proxy mechanism removed
(T094a)" above — in full, by removal. (Previously partially superseded by
§"2026-07-06 — docker-socket-proxy `CONTAINERS=1` read surface" on the
read-surface characterization only.) The prose below is retained verbatim
for the audit trail.

**Decision.** Stargate's local profile runs a digest-pinned
`tecnativa/docker-socket-proxy` container as the **only** service that
mounts `/var/run/docker.sock` from the host. The control plane (CP)
reaches it as `http://docker-socket-proxy:2375` over the compose-internal
network (compose service key `docker-socket-proxy` in
`compose/docker-compose.local.yml`, no host `ports:` mapping). This entry
documents **why a privilege-isolating proxy is used instead of mounting
the docker socket directly into the CP container**, the property the
proxy buys, the residual trust, and the mitigations recorded. The Tor
sidecar entry below (T017) covers a different concern (Tor binary
provenance) and is unaffected by this entry.

**Property bought.** A compromise of the Quarkus control plane (YAML
parser, gRPC server, future admin UI) does NOT escalate to host root,
because the CP holds no `docker.sock` handle and can only invoke the
GET-only surface the proxy exposes (`EVENTS=1`, `CONTAINERS=1`, all
other endpoint flags unset → default-deny; `POST=0` forbids container
spawn/kill/exec). Without the proxy, the CP would hold the host's
`docker.sock` handle directly, and any CP compromise (a malicious YAML
payload reaching a `Process.exec`, a gRPC parsing bug, a future
admin-UI auth bypass) is immediate host root — the Docker daemon runs as
root, and `POST /containers/create` with a bind-mount of `/` is a
one-step pivot. The proxy moves that pivot out of the CP's reach: the
CP can `GET /events` and `GET /containers/{name}/json` (the surface
`SidecarMonitor` per T039 depends on) and nothing else. **The same
property holds for the DP and Tor** (both also on `stargate-internal`,
see "Exposure surface" below) on the same condition — the proxy's
env-flag filter + HAProxy frontend + base closure behave as documented.
**The lockdown is runtime-verified by T019c when it lands; until then
it is asserted statically** by `compose/docker-compose.local.yml`'s
env-block + the `local_compose_test.sh` shape regex (Mitigation #2 +
§Analysis R2).

**Residual trust (Principle V).** The proxy itself IS in the TCB: **any
code-execution inside the proxy container** is host-root-equivalent,
because the proxy holds the `docker.sock` handle and `POST
/containers/create` with a bind of `/` is a one-step pivot — the Docker
daemon does the bind as root regardless of the UID of the process
issuing the call. "Code-execution inside the proxy" is wider than
"bypass of the env-flag filter": the env-flag filter is one layer in a
stack that also includes HAProxy (the proxy's HTTP frontend — verified
at T017a commit time via `docker image inspect` of the pinned image:
entrypoint `docker-entrypoint.sh`, cmd `haproxy -f
/usr/local/etc/haproxy/haproxy.cfg`, HAProxy version `2.2.33`,
`Config.User` empty → root per Mitigation #1 below), the
`docker-entrypoint.sh` shell script, the proxy image's base distribution
(per the upstream Dockerfile's `FROM haproxy:2.2-alpine`, which itself
derives from `alpine:3.x` — illustrative TCB enumeration; not
Stargate-side re-verified), and the transitive dependency closure of
all three. An HAProxy parsing bug, a
request-smuggling flaw, an entrypoint quoting bug, or a vulnerability
in the base image's `libssl`/`musl`/`pcre2`/`zlib`/`lua5.3`/etc.
yields code-exec inside the container without ever touching the
env-flag filter — exactly the way Tor's `libssl3` residual rode on
Debian's archive key (T017 residual bullet, §"Tor's transitive
dependency closure"). The proxy image's own transitive-dependency
closure is therefore part of this entry's TCB and sits OUTSIDE the
env-flag filter: a malicious or vulnerable HAProxy or base-image
component (or, for completeness, a future rebuild of
`tecnativa/docker-socket-proxy:0.3.0` at the same tag but a different
sha256 — pinned against by the digest) defeats the property bought,
with no Stargate-side verification reach. **Mitigation:** the digest
pin (Mitigation #1) means the closure is pinned as long as the digest
is pinned; the PR-cadence gate cannot detect a behaviourally-conforming
malicious component in the proxy's closure (same shape as T017 R4 /
libssl3).

This is **NOT** a defence against a local attacker with arbitrary code
execution on the host — THREAT-MODEL §3.1 ("local profile assumes local
code execution is already game-over") covers that. The residual is the
**narrower** claim that a CP-, DP-, or Tor-process-compromise alone
does not, on the happy path where the proxy's filter + frontend + closure
all behave as documented, pivot to host root through the docker socket:
the attack surface shrinks from "any compose-internal-service bug that
reaches the docker.sock handle directly" down to "either an upstream
proxy-component bug OR a service bug that additionally finds a
filter/frontend bypass."

**Exposure surface — three services can reach the proxy, not only the
CP.** Per `tests/contract/compose/local_compose_test.sh` M13, all four
services (`stargate-dp`, `stargate-control`, `tor`, `docker-socket-proxy`)
are attached to the single `stargate-internal` bridge network; the proxy
at `http://docker-socket-proxy:2375` is reachable from the CP, the DP,
and Tor. The property bought above holds for each of the three on the
same condition (the proxy's filter/frontend/closure behave as
documented). **The DP case is the most concerning pivot** because the
DP is the untrusted-bytes boundary (Constitution Principle I — the DP
parses SOCKS5/CONNECT bytes from the browser): a DP parsing bug →
DP-container code-exec → `docker-socket-proxy:2375` → host root is a
strictly more concerning vector than the CP case this entry leads with,
because the DP faces internet-supplied input the CP does not. Naming
the DP explicitly so an auditor does not conclude "the proxy isolates
only the CP." Tor-side compromise is covered by THREAT-MODEL §2.6
(compromised sidecar in the per-route privacy TCB) for the
anonymness-property side; the §2.6 → host-root-via-`docker.sock` pivot
is a Stargate-specific residual that this entry (not §2.6) carries.

**The `:ro` mount suffix is convention-only, NOT a security boundary.**
The `/var/run/docker.sock:/var/run/docker.sock:ro` mount in compose is
retained to document intent, but AF_UNIX sockets have no
kernel-enforced read/write direction — the proxy can still issue
write-direction Engine API requests (`POST /containers/create` etc.)
regardless of the mount mode. The actual enforcement of "observe but
cannot mutate" is the HTTP-level filter inside the proxy (the env-flag
lockdown below), gated at runtime by T019c. This honesty note mirrors
the comment block in `compose/docker-compose.local.yml`; do NOT rely on
`:ro` for isolation here.

**Mitigations recorded:**

1. **Digest-pinned image (Principle IV).** The image is pinned by
   multi-arch OCI index digest, the closest available analogue to "the
   exact tested bytes" across amd64/arm64 hosts:

   `tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2`

   Resolved via `docker buildx imagetools inspect` at T015 `/start` time.
   **Source of truth:** `compose/env/local.env.example`'s
   `DOCKER_SOCKET_PROXY_IMAGE=` line; `compose/docker-compose.local.yml`
   reads it via `${DOCKER_SOCKET_PROXY_IMAGE}`. Bumping is a manual
   promotion: resolve the new digest, update `compose/env/local.env.example`
   AND this entry in one PR, re-run `scripts/ground-check.sh` ONLINE to
   confirm the registry still serves the digest. The contract test
   `tests/contract/security-decisions/docker_socket_proxy_entry_test.sh`
   (T017a AT-1 M5) cross-checks the two locations and fails on drift.
   **Operator-override caveat:** this is the *example* source of truth;
   `scripts/stargate init` (T016) and the BYO-env path both
   write/let-the-operator-edit a gitignored `compose/env/local.env`. An
   operator who overrides `DOCKER_SOCKET_PROXY_IMAGE` in `local.env`
   runs a different image than the one recorded here, and no contract
   test catches the override. Operators MUST re-record any override as
   a superseding entry in this file before deploying.
   *No defense-in-depth user-isolation control is recorded here.* The
   pinned image's `Config.User` is empty (verified at T017a commit
   time via `docker image inspect
   tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2
   --format '{{.Config.User}}'` → empty = the proxy runs as **root**
   inside its container). This does NOT reduce the host-root-equivalent
   residual (the `docker.sock` handle is the pivot; Docker binds as
   root regardless of the calling UID — see "Residual trust" above);
   recording it only so an auditor does not assume a non-root proxy
   process. A future image bump that adds a `USER` directive would
   change this — verify at bump time via the same `docker image inspect`
   command and supersede this clause if so.
2. **Lockdown env-block + runtime gate (T019c).** The proxy service is
   locked to `EVENTS=1`, `CONTAINERS=1`, all other endpoint flags unset
   (`tecnativa/docker-socket-proxy` defaults unset flags to deny), and
   `POST=0` to forbid spawn/kill/exec. The compose env-block asserts
   the lockdown statically; the runtime lockdown contract test **T019c**
   (parallel Phase-2 ticket, not yet landed) gates it at compose-up
   time. Until T019c lands, the lockdown is asserted only by
   `docker-compose.local.yml`'s env-block and by the
   `tests/contract/compose/local_compose_test.sh` shape regex — see
   §Analysis R2.
3. **Compose-internal only (not reachable off-host).** The proxy service
   has **no `ports:` key** in `docker-compose.local.yml`; it is
   reachable only from the `stargate-internal` compose network, NOT from
   the host network and not from off-host. A non-routable proxy cannot
   be probed by an external attacker — they would need to first
   compromise a service on the `stargate-internal` network (CP, DP, or
   Tor — see "Exposure surface" above) to reach the proxy at all.

**THREAT-MODEL §3.1 cross-reference.** The residual-risk framing here
matches §3.1's "an attacker who gains local code execution can replace
the data-plane binary on disk, swap a sidecar image, or read the
inter-plane keys" — the local profile already assumes local code
execution is game-over, so the proxy-compromise residual is consistent
with the mode's threat model rather than a new assumption. The proxy
narrows the attack surface within that framing: it removes "CP/DP/Tor
bug → host root via `docker.sock`" from the local-attacker playbook on
the happy path where the proxy's filter + frontend + closure behave as
documented.

**Architecture spec §16.1 cross-reference.** `specs/000-architecture/spec.md`
§16.1 ("Auxiliary Infrastructure Containers") documents the same trust
model and explicitly defers the mitigation record to this entry
("Mitigations recorded in `SECURITY-DECISIONS.md` (entry created by
`specs/001-tor-route/` T017a)"). **The two artifacts have drifted on
two points as of T017a commit time** (this entry is the authoritative
resolution; §16.1 is the stale spec-side anchor pending reconciliation):

1. §16.1's mitigation list still names "proxy runs as the unprivileged
   user its upstream image declares" — verified FALSE at T017a (see
   Mitigation #1: `Config.User` is empty, the proxy runs as root).
2. §16.1's release-blocker sentence is CP-only ("The LAN and VPS
   profiles expose the CP to non-localhost callers…"); this entry
   widens it to CP/DP/Tor (see "Release-blocker" below).

Reconciling §16.1 is filed as follow-up **T018** (the sibling arch-spec
amendment ticket, whose mandate already includes "verify at
implementation time that… T017a's `SECURITY-DECISIONS.md` entry remains
the authoritative rationale"). Until T018 lands, §16.1's stale framing
is a known, filed, tracked gap — same shape as the THREAT-MODEL §8.6
gap T017 left for T082 (Constitution V — the model and the decision log
contradict until the spec sync lands). A future change to the proxy
mechanism MUST be revisited in both artifacts in the same PR
(reviewer-enforced today, not gated by an automated test; a follow-up
could add a contract test that diffs §16.1's `docker-socket-proxy`
block against this entry's prose anchors).

**Release-blocker for any future LAN or VPS profile feature spec.**
This mechanism is sized for the **local profile only** — the proxy is
reachable only from the `stargate-internal` compose network (CP, DP,
and Tor; see "Exposure surface" above), so its exposure surface is
CP/DP/Tor-process-compromise, with the DP the most concerning pivot
since it faces internet-supplied input the CP does not. The local
profile binds no non-loopback interface, so no off-host caller can
reach the proxy. The LAN and VPS profiles expose the CP (and the DP,
under any future split-tunnel configuration) to non-localhost callers
— devices on the household LAN, or anyone with the WireGuard/Tailscale
credential — and shift the compromise-probability calculus materially.
**Any future LAN or VPS profile feature spec MUST revisit this entry
(and likely replace the proxy mechanism — e.g. with a CP→host RPC over
a dedicated UDS with a purpose-built daemon) before that profile's
compose file ships.** §16.1 carries a sibling release-blocker sentence
(this entry + §16.1 are the two anchors that MUST be revisited
together); note that §16.1's release-blocker is currently narrower
(CP-only) than this entry's (CP/DP/Tor) — see "Architecture spec §16.1
cross-reference" above for the drift reconciliation plan under T018.

---

## 2026-07-04 — Tor sidecar trust rationale (FR-015)

Superseded by: [T160 Tor security promotion](#2026-09-12--tor-04912-security-promotion-and-exact-package-content-pins-t160), for the Tor version/hash selection and same-version content-integrity claim only.
Superseded by: [T184 Debian snapshot rollback refusal](#2026-09-30--refuse-rolled-back-debian-snapshot-metadata-for-the-tor-image-t184), for the T099 claims that the snapshot run and `=version` pins freeze the closure and need no Valid-Until handling only.
Superseded by: [T191 Tor repository erratum](#2026-10-02--erratum-the-tor-repository-drops-the-pinned-build-with-each-new-bookworm-build-t191), for the T099 "Rotation" bullet's framing of an old `.deb` removal as possible rather than recurring only.

**Decision.** Stargate builds its own Tor sidecar image
(`sidecars/tor/Dockerfile`) from a digest-pinned `debian:12-slim` base,
installing the `tor` package from the Tor Project's official Debian apt
repository (`deb.torproject.org`), with the Tor Project signing key pinned by
fingerprint and verified at build time. The image is `stargate/tor` (service
key `tor` in compose, T015). **Only the base image is pinned today** — the
final composed image digest lands at release tag time via T081 (see
"Final-image digest values" below); until then the supply chain is
base-pinned + key-verified, NOT fully image-pinned.

**Resolves (pending T082 amendment of) THREAT-MODEL §8.6 "Sidecar maintainer
trust"** — which currently frames this as an unresolved decision to "choose a
community maintainer." This entry resolves it differently (build in-house
from the Tor Project's own apt repo rather than pick a third-party image
maintainer). THREAT-MODEL §8.6 itself MUST be amended in lock-step to stop
contradicting this entry — that spec edit is filed as follow-up **T082**
(sibling to T018, which amends arch §7 for the same decision). Until T082
lands, §8.6's prose still reads as "unresolved" — this entry is the
authoritative resolution; the model sync follows.

**Rationale — why `deb.torproject.org` over a fork or an upstream image
(THREAT-MODEL §2.6 — the Tor sidecar is in the per-route privacy TCB).**

1. **The Tor Project publishes no official Docker image.** A community
   Docker image (e.g. on Docker Hub) would be a third-party rebuild of
   unknown provenance with no contract binding it to the Tor Project's own
   distribution. Stargate's privacy guarantee depends on the `tor` binary
   being the Tor Project's own build; a third-party image breaks that.
2. **`deb.torproject.org` is the Tor Project's own distribution channel** —
   the same apt repo the Tor Project ships for Debian users. Building from
   it on a pinned Debian-slim base is the closest available analogue to
   "the Tor Project's own distribution" inside a container. The `tor`
   package installed is the Tor Project's signed Debian package, not a
   fork and not a distro-shipped rebuild.
3. **Pinned base + signed-by repo binding** (Principle IV): the Debian-slim
   base is pinned by digest (below); the apt repo is bound to the verified
   Tor Project key via `signed-by=` only — no global `apt-key add`. A
   compromise of the Debian archive key would NOT grant signing trust over
   the Tor repo.
4. **Build-time TOFU resistance.** The Tor Project signing key is fetched
   over TLS from `deb.torproject.org` and verified by fingerprint. To close
   the build-time-MITM bypass (THREAT-MODEL §2.3 — an active adversary on
   the build host's upstream TLS could append a second attacker-controlled
   primary key to the `.asc` file, pass the fingerprint check on the
   legitimate first primary, and gain `signed-by=` trust for malicious
   packages), the Dockerfile asserts `PUB_COUNT==1` — exactly one primary
   key in the fetched file — before dearmoring. Either check failing fails
   the build loudly. See `sidecars/tor/Dockerfile` header comment for the
   full bypass analysis.

**Apt-key fingerprint (pinned, verified at every build):**

`A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`

This is the canonical Tor Project archive-signing key. It is the single
source of truth in `sidecars/tor/apt-key.fingerprint`; this file quotes it
verbatim; `sidecars/tor/Dockerfile` reads it at build time. The contract
test `tests/contract/security-decisions/tor_entry_test.sh` asserts all three
locations agree. **Rotation policy:** the Tor Project rotates this key every
few years. When it does, every Tor-sidecar build fails loudly at the
fingerprint check (intended). The rotation is a **manual, review-driven
update**: in one PR, `sidecars/tor/apt-key.fingerprint`, the fingerprint
quoted here, and (if the Dockerfile's verification logic is affected) the
Dockerfile are updated together, the new fingerprint is confirmed against
the Tor Project's published rotation announcement, and the contract test
goes green again. No automated key refresh — Principle IV's manual-promotion
discipline applies to signing keys exactly as it applies to image digests
(THREAT-MODEL §5.9 — update-channel compromise). **Revocation without
replacement:** if the Tor Project revokes the signing key and ships no
immediate successor, every Tor-sidecar build fails loud and Stargate ships no
Tor-route update until the Tor Project publishes a successor; the new
fingerprint is then sourced from a Tor-Project-issued statement
(`deb.torproject.org` homepage or the `tor-project@lists.torproject.org`
list archive), not from the `.asc` file alone (which an attacker could rotate
to their own key under a revoked-but-still-served key).

**Debian-slim base digest (pinned, both stages):**

`debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df`

Multi-arch OCI index, resolved via `docker buildx imagetools inspect
debian:12-slim` (registry-direct, not local cache). Pinned in BOTH stages of
`sidecars/tor/Dockerfile`; the two stages stay in sync (the contract test
asserts a single distinct digest across the file). The same digest is reused
by `scripts/subcommands/init` (T016) for the key-gen helper container, so
the TCB base is one image, not two. Bumping this digest is a manual
promotion: resolve the new digest online, update both Dockerfile stages +
this entry, run the contract suite.

**Debian archive snapshot pin — T099 (immutable build inputs, Principle IV).**

The base image + signing key are pinned, but until T099 the resolved
*package set* was not: stage 2's `apt-get install tor` resolved tor's
link-time closure (libssl3, libevent-2.1-7, zlib1g, libc6) fresh from
Debian's mutable archive index on every build, so two builds of the same
commit could select different bytes. T099 pins the Debian archive to an
immutable `snapshot.debian.org` run and pins every directly-installed
package to an explicit `=version`:

- **Snapshot run:** `20260714T082229Z` (bookworm 12.15; archive `Date`
  2026-07-11). Pinned in both Dockerfile stages + recorded here; the
  cross-file agreement is gated by
  `tests/contract/security-decisions/tor_build_inputs_test.sh` (B6).
  `snapshot.debian.org`'s InRelease carries no `Valid-Until` (it never
  expires), so no `Check-Valid-Until` defeat is applied; the snapshot is
  buildable indefinitely.
- **Transport — HTTP, not HTTPS.** The base image ships no `ca-certificates`,
  so an HTTPS bootstrap would be circular (ca-certificates is the first
  package installed). Integrity is NOT transport-based: apt verifies the
  InRelease PGP signature (Debian archive keyring, shipped in the base) and
  every `.deb` sha256 against the signed Packages index — a MITM cannot forge
  either, so signed metadata is the load-bearing guarantee (TLS would be
  defense-in-depth only).
- **Pinned packages (sha256 retained for audit):**

  | package | version | sha256 | source |
  |---|---|---|---|
  | ca-certificates | `20230311+deb12u1` | `0d5f444f594e48c1e16a41d8fc628a09b24c658916a1274025c2330f2a802bed` | snapshot (both stages) |
  | curl | `7.88.1-10+deb12u15` | `0dd9b6bf7a0bd11af2d68a52ec44c2a223fa7c11f9104c36ce1047e1137d4a8f` | snapshot (stage 1 only) |
  | gnupg | `2.2.40-1.1+deb12u2` | `d3f860cf16da5d61875a324859045fd1f4a888ed0ddef55d7e9f977dd729a76e` | snapshot (stage 1 only) |
  | netcat-openbsd | `1.219-1` | `85adebc045f48eb9a91515202a49940a0a57eff790223402333253ff121dfbdd` | snapshot (stage 2) |
  | tor | `0.4.9.11-1~d12.bookworm+1` | `1a9fa54dece42c21fffd142963ad5e13eec735654b95f82386d7c18702145d28` | `deb.torproject.org` (Tor Project build — NOT Debian's archive rebuild `0.4.9.11-0+deb12u1`, per FR-015) |

  Transitive deps (libssl3 `3.0.20-1~deb12u2`, libevent-2.1-7
  `2.1.12-stable-8`, …) are frozen by the snapshot and verified by apt; their
  hashes ride the signed Packages index. The gated reproducibility property
  (stable package manifest across cold rebuilds) is asserted by
  `tests/reproducibility/tor_sidecar_manifest_test.sh`.

- **Rotation.** Refreshing the snapshot is a manual, review-driven PR
  (Principle IV): bump the `snapshot.debian.org` run timestamp, every
  `=version` pin, and the sha256 table here in one commit; the contract test
  re-confirms the timestamp agrees cross-file; the reproducibility test
  re-confirms the manifest is stable. The Tor package version rotates when the
  Tor Project ships a new `bookworm` build — caught by the same manual PR.
  `deb.torproject.org` is NOT snapshotted (the Tor Project offers no frozen
  index); its immutability is the `=version` pin + apt's sha256 verification
  against its signed Packages index, with the residual that the Tor Project
  could remove an old `.deb` (a removal fails the build closed → manual
  refresh, exactly the Principle IV promotion discipline).

**Final-image digest values — RELEASE-TAG-TIME (T081), NOT YET PINNED.**

FR-015's literal text requires that "the final composed image MUST be pinned
by sha256 digest in `compose/docker-compose.local.yml`." For the three
Stargate-built images (`stargate/stargate-dp`, `stargate/stargate-control`,
`stargate/tor`) this is **currently unmet and release-blocking**: compose
(T015) ships them as `build:` directives for the Phase-2 scaffolding
horizon, so no final-image digest exists to pin. The gap is closed by
**T081**'s `.github/workflows/release.yml`, which at release tag time:
builds each image, pushes it to GHCR, captures its `sha256:` digest,
**cosign**-signs it keyless (Rekor transparency log entry), emits an **SBOM**
(SPDX), and appends the resolved digest values + signing/SBOM/Rekor
references to this file (and to a sibling `compose/docker-compose.release.yml`
that pins them). Until T081 lands, deployment today is `docker compose build`
from source; the verified-pull path is post-T081. **This entry does NOT
record final-image digests because they do not yet exist; recording a
fabricated value would violate the honest-threat-model Principle V.** The
external-image digest that IS pinned today (the docker-events filter aux
container in compose) is documented by a separate entry (T017a).

**Residual risk (THREAT-MODEL §2.6, §5.8).**

- The Tor sidecar remains in the per-route privacy TCB: a backdoored `tor`
  binary sees SOCKS5 destinations, circuit state, and exit-visible cleartext.
  Pinned-digest selection + build-time key verification + the contract-test
  gate (FR-016) reduce but do not eliminate this. The mitigation is "trust
  the Tor Project's own distribution channel, verified end-to-end at build
  time," not "the sidecar is trusted by construction."
- **Tor's transitive dependency closure rides on Debian's archive trust, not
  the Tor Project's.** The `tor` package's link-time dependencies —
  `libssl3` (OpenSSL; carries Tor's authenticated TLS to guards — the
  literal carrier of circuit-setup and relay-authentication crypto),
  `libevent-2.1`, `zlib1g`, `libc6` — are pulled from Debian's main archive
  under Debian's archive signing key, NOT from `deb.torproject.org` under
  the Tor Project's key. A malicious `libssl3` in Debian's archive (or a
  compromised Debian archive mirror) compromises Tor's guard TLS and defeats
  the core anonymity property the sidecar exists to provide, with no
  Stargate-side verification reach. This is the single most
  security-relevant component of the sidecar's TCB and it sits OUTSIDE the
  fingerprint-verified channel. **T099 closed the reproducibility half of
  this gap** — the Debian archive is now pinned to an immutable
  `snapshot.debian.org` run with every package `=version`-pinned, so the
  closure (libssl3 included) is frozen and auditable: every build selects
  the SAME bytes, and the exact `libssl3` `3.0.20-1~deb12u2` is recorded.
  The TRUST half remains residual: the closure still rides Debian's archive
  signing key (not the Tor Project's), and neither the snapshot pin nor the
  contract-test suite detects a malicious library that conforms
  behaviourfully — the pin makes it auditable, not trustworthy. The
  mitigations are Debian's own archive-signing integrity (out of Stargate's
  control) and the contract-test suite gating Tor's documented behavioural
  invariants. Residual. (THREAT-MODEL §2.6, §5.9.)
- The build-time TLS fetch of the signing key trusts `deb.torproject.org`'s
  TLS at build time (a CA- or BGP-level adversary on the build host's
  upstream could attempt delivery of a malicious key file); the
  `PUB_COUNT==1` assertion plus fingerprint pin closes the documented
  bypass, but a fully compromised CA + a key-collision attack is residual
  (THREAT-MODEL §5.9).
- The Debian base image and the `ca-certificates`/`tor`/`netcat-openbsd`
  packages installed in stage 2 are trusted on Debian's own archive signing
  (out of Stargate's control); Principle IV's contract-test gate catches
  behavioural regressions on Tor's documented invariants but cannot detect a
  malicious Debian package that conforms behaviourally.

---

## Reserved: adversarial-review findings (Phase N+)

This section is reserved for `stargate-redteam` and `stargate-perf` findings
accepted (mitigated, risk-accepted, or deferred-with-rationale) in any phase,
per Constitution Principle VIII. Each accepted finding gets a dated
`##` entry below stating: the finding, the acceptance rationale, the
mitigation or the explicit risk acceptance, and a cross-reference to the
artifact (test, code, or threat-model row) that carries the mitigation.

Initially empty. The end-of-feature `stargate-redteam` + `stargate-perf`
passes against the completed `001-tor-route` feature populate this section;
their findings either resolve in-code (no entry needed) or land here as
accepted-finding rationales.

(No entries yet.)
