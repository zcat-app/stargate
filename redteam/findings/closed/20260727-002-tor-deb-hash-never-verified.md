---
id: 20260727-002-tor-deb-hash-never-verified
status: closed
severity: major
principle: [IV, VI]
threat-model: 5.9
location: sidecars/tor/Dockerfile:163-167
first-seen-run: 20260727-8bc5f6a
first-seen-date: 2026-07-27
fix-commit: 55c567783a084354ba6321b6ecd0f7b88651f574
decision-ref: SECURITY-DECISIONS.md "2026-09-12 — Tor 0.4.9.12 security promotion and exact package content pins (T160)"
---

# The `tor` .deb comes from a mutable repo and its recorded sha256 is verified by no build step

## What the code does

`sidecars/tor/Dockerfile:156-162` installs every Debian package from an immutable
`snapshot.debian.org/archive/debian/20260714T082229Z` run with explicit `=version` pins.
`:163-167` then adds `deb.torproject.org` — a live, mutable repository with no frozen index
— and installs `tor=0.4.9.11-1~d12.bookworm+1` from it.

The sha256 of that .deb is recorded twice, at `sidecars/tor/Dockerfile:80` and
`SECURITY-DECISIONS.md:787`
(`1a9fa54dece42c21fffd142963ad5e13eec735654b95f82386d7c18702145d28`), and **read by
nothing**: there is no `sha256sum -c`, no `apt-get download`, no hash comparison anywhere in
the build.

```
$ grep -n "sha256sum\|apt-get download" sidecars/tor/Dockerfile
(no hits)
```

The reproducibility gate `tests/reproducibility/tor_sidecar_manifest_test.sh:41` compares
`dpkg-query -W -f='${binary:Package}=${Version}\n'` — **names and versions only**. dpkg
retains no .deb content hash, so the test cannot observe a content change at a fixed
version. `BUILD-DIFFS.md:39-47` instructs auditors **not** to treat a differing
`stargate/tor` image digest as a finding, and to verify via this manifest comparison instead.

## Why it leaks

Constitution Principle IV: *"A privacy tool's Trusted Computing Base must not change
silently."* Principle VI's T099 tier states the gated property for this image is *"a
byte-stable package manifest."* For the single most security-relevant package in the image,
neither holds.

An adversary with publish access to `deb.torproject.org` — repository compromise, or
compromise of the archive signing key — uploads a backdoored `tor` under the identical
version string `0.4.9.11-1~d12.bookworm+1`. apt verifies it against the repo's own re-signed
`Packages` index and installs it happily. Every subsequent Stargate rebuild silently ships
the backdoored Tor:

- `tor_sidecar_manifest_test.sh` passes — same `name=version`.
- The snapshot-pin contract test passes — the Debian side is unchanged.
- The one observable difference is the image digest, which is exactly the signal
  `BUILD-DIFFS.md` tells the auditor to ignore.

Per `SECURITY-DECISIONS.md`'s own residual-risk text, a backdoored `tor` binary *"sees
SOCKS5 destinations, circuit state, and exit-visible cleartext"* — total compromise of the
route this feature exists to provide.

`SECURITY-DECISIONS.md:801-805` anticipates only the *removal* case ("a removal fails the
build closed"). The *replacement-at-same-version* case is unrecorded and ungated.

## Suggested fix

**Default (cheapest, closes the audit gap end to end):** extend
`tests/reproducibility/tor_sidecar_manifest_test.sh` to additionally assert
`sha256sum /usr/bin/tor` (and `/usr/bin/tor-gencert`) against per-architecture values
recorded alongside the existing manifest, and add those values to the
`SECURITY-DECISIONS.md:787` table. A same-version content swap then fails the release gate
rather than passing it silently.

**Stronger alternative (fails the build, not just the test):** in the Dockerfile, replace the
direct install with

```dockerfile
apt-get download tor=0.4.9.11-1~d12.bookworm+1 \
 && echo "<sha256>  tor_<ver>_<arch>.deb" | sha256sum -c - \
 && apt-get install -y --no-install-recommends ./tor_*.deb
```

Trade-off: the Dockerfile is built multi-arch, so this needs a per-arch hash table and a
`TARGETARCH`-keyed lookup — more moving parts than option 1, but it fails closed at build
time rather than at release-test time. Take option 1 as the default; option 2 if the project
wants build-time enforcement.

Amend `SECURITY-DECISIONS.md:801-805` to name the replace-at-same-version residue, and
`BUILD-DIFFS.md:39-47` so the documented auditor procedure includes the binary hash check.

## Regression test

The strengthened `tor_sidecar_manifest_test.sh` is itself the regression line (Principle VII:
infrastructure gets smoke tests at minimum). Add a negative control that feeds it a synthetic
manifest with one mutated binary hash and asserts a non-zero exit — proving the gate actually
catches the failure mode, the same discipline
`tests/internal/loginvariants/loginvariants_test.go` applies to the leak scan.

## Related

- Partially invalidates `SECURITY-DECISIONS.md` "2026-07-04 — Tor sidecar trust rationale
  (FR-015)" and its T099 snapshot-pin addendum.
- Constitution Principle VI's Tor-sidecar reproducibility tier (added by T099) is the claim
  that does not currently hold.
- Found during the 2026-07-27 milestone audit (`.scratch/audit.md`, finding S2).

## Closure — 2026-09-12

T160 downloads the exact architecture-specific Tor package, verifies it against an independently
reviewed SHA256 lock and installs from the checked local file with further downloads disabled.
Its regression rejects same-name/version byte substitution, refetch, missing pins and unsupported
architectures. Round-one review also found that the mutable Tor repository could supply an
unchecked dependency while the Tor bytes remained valid; the delivered installer now excludes
that repository from dependency resolution and installation, with higher- and same-version APT
source-selection controls. Native builds, a real wrong-hash negative build, two cold package-
manifest comparisons and the full gate passed. Codereview and redteam approved exact snapshot
`5494521621dccc84d55ca179ad81e51e10816d23015b9dc6b6f6f738337c4130` in round two.

This closes the package-substitution finding. It does not establish live Tor isolation or authorize
promotion; T161 owns the retained failed T058 evidence and blocks deployment/release promotion.
