---
id: "T136"
title: "Prevent cross-site first-party isolation collisions"
status: in-progress
created: "2026-09-12"
last_updated: 2026-09-13
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T053", "T139", "T156"]
parallel: false
files_budget: 14
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T053"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T136: Prevent cross-site first-party isolation collisions

## Context

M3: actual router probes collapse alice.co.uk/bob.co.uk and alice.github.io/bob.github.io onion subrequests onto equal SOCKS usernames.

## Analysis

- **Must hold (Principles I/III/VII/VIII):** every Tor isolation partition contains the
  authenticated device, browser profile and initiating top-level site. DNS sites use Firefox
  153's native public-and-private suffix boundary; onion services and IP literals cannot collapse.
  Missing or untrustworthy top-level context produces no routable identity and never substitutes
  the destination. The SOCKS username is deterministic, bounded and collision-resistant without
  revealing the bearer; the password remains the bearer, `proxyDNS` remains true, and the data
  plane continues to forward the username opaquely with an empty upstream password. Each property
  has a named regression written before production code.
- **Gated before T136:** the extension suites cover ordinary document-over-origin precedence,
  onion/IPv4 preservation, selected malformed inputs, proxy descriptor shape and `proxyDNS`, but
  permit last-two-label and destination fallbacks. Data-plane
  `TestForwardPassesUNAMEVerbatimAsUpstreamUsername` already proves arbitrary UNAME forwarding and
  zero-length upstream PASSWD. These gates do not prove the complete partition or a real circuit.
- **Promoted into the green gate by T136:** native ICANN/private/wildcard/exception suffix results
  and API-failure handling; manifest rejection below Firefox 153; exact document-ancestry and
  stale-document races; scheme/port/onion/IPv4/IPv6 canonicalization;
  same-partition stability and distinct site/device/profile/private-context identities; fixed HMAC
  vectors and the 255-byte SOCKS bound; first-install/profile and token-rotation races; and router
  regressions using one onion destination under distinct `co.uk` and `github.io` top-level sites.
- **Residue:** Node mocks cannot prove real Mullvad Browser metadata, committed-navigation timing,
  private-window behavior or Promise proxy descriptors. T126/T155 own same-target live Tor-circuit
  evidence and a credential-fusion control; T157 owns actual cancellation and proof of no Direct,
  system-proxy or unintended-route packets when identity is unavailable. A browser update can
  change the native suffix result and intentionally start a new identity; copied/compromised
  profiles can copy their local nonce. These
  limits remain explicit rather than being inferred green from unit tests.

### Grounded isolation contract

- Require Gecko 153 or newer in the manifest and use native `publicSuffix.getDomain()` with its
  default punycode, ICANN-and-PRIVATE behavior. Never enable `allowPlainSuffix` or
  `allowUnknownSuffix`; `null`, exceptions and unexpected results are identity-unavailable. The
  extension performs no suffix-data network fetch. Mullvad Browser Alpha 16.0a11 / Gecko 153.2.0
  is development grounding only; stable Mullvad Browser on Gecko 153+ with MV2 remains a release
  gate.
- Sites are scheme- and port-independent. HTTP(S) DNS hosts reduce to registrable domains; complete
  normalized onion hostnames and canonical IPv4/IPv6 literals remain whole. Hostless/opaque URLs,
  unsupported schemes and public-suffix-only names are unavailable rather than guessed.
- A main-frame navigation uses its requested URL. Frame-zero subresources use a present valid
  `documentUrl` bound to the request's `documentId`; committed `documentId`/`parentDocumentId`
  ancestry supplies nested-frame and tab-associated worker requests. A new top-level document
  retires prior tab bindings and in-flight derivation rechecks its exact binding.
  `documentUrl` remains higher precedence than `originUrl`, while `originUrl`
  alone is not trusted when it may identify an intermediate resource such as a stylesheet.
  Redirected main frames use the new navigation target; redirected subresources retain the
  committed top-level site. Missing cache, detached workers and opaque top-level parents produce
  identity-unavailable. T157, not this ticket, owns turning that result into browser cancellation.
- Persist a random 32-byte browser-profile id in `storage.local`; normal/private and contextual
  identities are explicit inputs. Derive the username as 68 ASCII bytes: `sg1:` plus the full
  lowercase hex HMAC-SHA-256 of a versioned, fixed-order JSON string containing profile id,
  private/container context and a type-tagged canonical site, keyed by the device bearer token.
  Async derivation snapshots the token generation and rejects stale completion after a token
  change. Token rotation intentionally starts a new device partition; profiles sharing a copied
  nonce remain a documented residue.

## Acceptance

1. Before production code, write and observe failing router-level tests with identical device
   credentials, browser-profile state and onion destination but distinct initiating top-level
   documents under `alice.co.uk`/`bob.co.uk` and `alice.github.io`/`bob.github.io`; require distinct
   bounded usernames. Add same-site equality and distinct-device/profile/private-context controls.
2. Pin Gecko `strict_min_version` to `153.0` and use native `publicSuffix.getDomain()` defaults.
   Test ICANN, PRIVATE, wildcard, exception, IDNA, unknown and public-suffix-only results plus API
   failure independently. Never enable unknown/plain-suffix fallback or fetch suffix data at
   extension runtime.
3. Specify and test the context matrix above: document/origin precedence, top-level navigation,
   redirects, exact document ancestry, document replacement during async HMAC, nested frames,
   tab-associated and detached workers, opaque parents, initiating-site HTTP(S) scheme/port
   handling, `.onion` destination selection across HTTP(S)/WebSocket, complete onion identities
   and canonical IPv4/IPv6 literals. A destination hostname is not the fallback for unavailable
   initiating context.
4. Persist and validate browser-profile identity, include device/profile/site plus private/container
   context in the exact HMAC encoding above, and test fixed vectors, maximum length, concurrency,
   storage/crypto failure and token-rotation races. Preserve `proxyDNS: true`; never put the bearer
   or its literal bytes in the username, errors, route state or Tor-side password.
5. Before production edits, run the existing data-plane forwarding test as peer compatibility
   evidence and record its limit: it proves opaque UNAME and empty upstream PASSWD, not real
   circuits. Run the relevant extension suites, packaging/reproducibility checks and
   `scripts/verify.sh`, then both required independent reviews. Record unavailable live-browser and
   same-target circuit evidence honestly under the T126/T155/T157 owners.

## Out-of-scope

Popup semantics (T150), runtime hardening policy, T157's protected-request cancellation behavior,
unrelated routing features, suffix-data fetching, or claiming T126/T155 live-circuit evidence.
T136 may update the pre-existing `firstparty.test.js`, `firstparty.edges.test.js` and
`router.test.js` assertions only where the new constitutional contract replaces their historical
last-two-label, destination-fallback, literal-username or context assumptions. It may update
`manifest.test.js` only to pin Firefox 153+, native-suffix script removal and the
`webNavigation` permission.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

On 2026-09-13 the user authorized targeting the newest Mullvad Browser generation instead of an
ESR-140 compatibility path. The repository offered Alpha 16.0a11; its extracted, uninstalled
package reported Gecko 153.2.0 (`BuildID=20260902080000`). Host installation remained unchanged
because `sudo` required interactive credentials. The release gate requires stable, not alpha.

Tests-first evidence: the original router produced equal usernames for the same onion destination
under `alice.co.uk`/`bob.co.uk` and `alice.github.io`/`bob.github.io` before production changes.
After the Firefox-153 decision, the revised native-suffix/document-identity/manifest tests were
run against the bundled-PSL implementation and failed (20 router, 6 edge, 8 first-party and 2
manifest cases). The pre-existing data-plane
`TestForwardPassesUNAMEVerbatimAsUpstreamUsername` passed; it proves opaque username forwarding
and empty Tor-side password only, not circuit separation. Local Node is 18.19.1, below the pinned
Node 20 CI version, so CI remains authoritative.

Round-1 correctness reviews required stale-document retirement across pre-context async work, a
non-vacuous onion redirect control, WebSocket `.onion` routing without a scheme downgrade, and an
externally grounded HMAC reference vector. Before the round-2 production fix, the new stale-document
and WebSocket regressions were run together: 22 router tests passed and those 2 tests failed. The
redirect test was strengthened to assert a SOCKS result equal to a clean new-target navigation and
different from the old partition; it already passed, confirming a test-integrity rather than a
production defect. Python's standard-library HMAC independently reproduced the pinned `sg1:` vector.

Round 2 satisfied both round-1 items (the WebSocket regression re-verified by reviewer mutation;
the HMAC vector independently recomputed via python3 and node crypto) but returned one new Major
finding: the manifest omitted the Firefox `publicSuffix` API permission, so the namespace would not
be injected in the real browser and every DNS-site derivation would fail closed to DIRECT — the
Node suite stayed green only because it hand-mocks `browser.publicSuffix`. The round-3 fix declares
`publicSuffix` in `manifest.json` permissions (the M2 required list was updated first and observed
failing), and records the permission in arch §14.2 and the foundation-boundaries contract. The
round-2 Minor finding named T142 hunks inside this review range: those are the separately
committed, maintainer-approved docs commit 755a1c3 ("docs: refine T142 reviewer isolation
acceptance"), carried in-range only because T136's pinned base SHA fcfe411 predates that commit;
they are not part of T136's candidate.
