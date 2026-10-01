# Mullvad Browser hardening — live end-to-end verification

> Release-cadence. NOT run by `scripts/verify.sh` on the hermetic PR path.
> Run manually before a release tag, and whenever the browser-hardening
> boundary (Constitution Principle III bullet 3; architecture spec §14.5)
> is touched. This is the **real-browser** proof that the externally
> verified precondition holds; a green Node unit over invented prefs is
> explicitly NOT evidence (sol-review finding B4).

## Why this exists

Stable Firefox WebExtensions APIs do **not** expose `network.trr.mode`
(DoH), `network.dns.over_tls.*` (DoT), or `network.http.http3.enable`
(HTTP/3 / QUIC). The Stargate extension therefore cannot read or enforce
those prefs at runtime — it gates only WebRTC
(`privacy.network.peerConnectionEnabled`) and SOCKS5h (`proxy.ProxyInfo`).
The DoH/DoT/HTTP-3 guarantee is an **externally verified precondition** on
the target-browser profile, verified out-of-band against a test profile
that models the target browser's hardened defaults. This directory is
that out-of-band verification.

**Pref-source caveat (redteam m1).** This test reads the profile's
`prefs.js` `user_pref(...)` entries. Hardened distributions sometimes
enforce prefs via `lockPref` / `policies.json` / distribution config,
which are NOT written to `prefs.js` as `user_pref`. The test profile
must therefore be one that writes these four prefs as `user_pref` (so
the grep sees them), OR the test must be extended to read *effective*
pref state via Marionette/`about:config` (deferred to Phase 5+). A
correctly-locked stock distribution that does not write `user_pref`
lines would false-RED; this is a known limitation of the automated
floor, not a pass/fail on the distribution.

Reference: `docs/process/workflow.md` §"Live end-to-end verification" —
the live layer proves ONLY what the contract-test layer structurally
cannot see (here: the real browser profile's preference state, which no
hermetic test can inspect).

## Classification

- **Transport-relevant**: yes — the real browser's preference state and
  the real extension's `proxy.onRequest` behaviour are invisible to
  hermetic contract tests.
- **Cadence**: release (before a release tag), and on any change to
  architecture spec §14.5, THREAT-MODEL §5.3/§5.4/§5.5, or the
  Constitution Principle III bullet 3 amendment (T091).
- **Hermetic substitute**: none. A Node mock over `browser.privacy.*`
  proves nothing about the four hardening surfaces (the API does not
  exist for three of them).

## Preconditions (a human prepares these)

1. **Mullvad Browser** installed at a known path
   (`$MULLVAD_BROWSER_BIN`, default
   `/opt/mullvad-browser/Mullvad Browser` on Linux).
2. A **dedicated test profile** (do not use your daily profile). The
   profile's `prefs.js` is the source of truth for the four prefs below.
3. The **Stargate extension** built and loadable
   (`bash extension/package.sh` → `extension/dist/stargate-*.zip`).
4. An **allowlisted foreign extension** (Mullvad Browser's default uBlock
   Origin) and a **disallowed** one (any trivial extension) installed in
   the test profile, to exercise the foreign-extension inventory
   (architecture spec §14.5 Part 3; THREAT-MODEL §2.7).

## What it verifies

| # | Property | Source | How |
|---|----------|--------|-----|
| 1 | DoH off: `network.trr.mode == 5` | arch §14.5 Part 1; FR-004 | read `prefs.js` from the test profile |
| 2 | DoT off: no `network.dns.over_tls.*` family, or all-false | arch §14.5 Part 1; FR-004 | read `prefs.js` |
| 3 | HTTP/3 off: `network.http.http3.enable == false` | arch §14.5 Part 1; FR-004 | read `prefs.js` |
| 4 | WebRTC off: `media.peerconnection.enabled == false` (the Firefox `prefs.js` pref; the extension's runtime gate reads the same state via the stable `privacy.network.peerConnectionEnabled` API, which wraps it — the API path is NOT itself a `prefs.js` key) | arch §14.5 Part 1/Part 2; FR-004 | read `prefs.js` (automated in `run.sh`) AND assert the extension's runtime gate agrees (manual Part 2) |
| 5 | Foreign-extension inventory: allowlisted present, disallowed flagged | arch §14.5 Part 3; THREAT-MODEL §2.7 | load the extension, read `storage.local.hardening.lastAuditResult` |
| 6 | Fail-closed routing: with WebRTC forcibly enabled, `proxy.onRequest` returns no routable Tor descriptor for a `.onion` request — only the T186 unreachable sink `[{socks, file:///dev/null/stargate-blocked, proxyDNS}, null]`, never `null` (which Gecko treats as Direct) | FR-004/FR-004a; Constitution III | flip `peerConnectionEnabled` true, assert the extension's `hardeningOk` flag is false and the result is the sink; `probe.py --only blocked-proxy` proves the network outcome |

`probe.py` (T195) never injects `media.peerconnection.enabled` into a hardened
session: it carries only the value in the shipped `browser-profile/user.js` (Mullvad
Browser's own default is enabled, so a template without it fails the Tor positive
controls). WebRTC is forced on only in the explicit negative-control session, which
also asserts that Gecko displays the failure notification.

Properties 1–4 (the `prefs.js` reads) are **automated in `run.sh` (Part 1)**
— these are the load-bearing checks, because the WebExtensions API does
not expose prefs 1–3 and the `prefs.js` read is the ONLY verification for
them. Property 4 is double-checked (profile pref + extension runtime
gate). Properties 4-runtime/5/6 are **manual Part 2** (the extension code
T055 does not exist yet, so runtime behaviour cannot be automated until
Phase 5+). A release-runner must complete both parts before tagging;
`run.sh`'s GREEN covers only Part 1.

Properties 1–3 have **no hermetic substitute** (the WebExtensions API does
not expose them); they are the load-bearing reason this live-e2e test
exists. Property 4 is double-checked (profile pref + extension runtime
gate). Properties 5–6 exercise the extension's real behaviour in the real
browser.

## Connection-level probe (`probe.py`; T157, T186)

`probe.py` drives Mullvad Browser through geckodriver in ephemeral
profiles with calibrated catchers (destination, ordinary proxy, SOCKS)
and writes a JSON report to `--report-out`. T157's modes cover
cancellation and no-fallback with the real extension. T186 adds two modes
that run **without** a cancel listener and also capture name resolution
(`strace` of the browser's port-53 sockets and MOZ_LOG `nsHostResolver`;
`strace` must be installed):

- `--only descriptor-matrix` — a generated proxy-only test extension
  returns fixed results (`null`, a SOCKS impostor, the Unix-socket sink,
  `https` targets with plain/TLS impostors) for `.onion`, `.onion.`,
  mixed-case and unmapped names, with positive controls for every surface.
- `--only blocked-proxy` — the candidate package with only its cancel
  listener removed; blocked requests (missing token, closed hardening) must
  reach no destination, proxy, SOCKS or resolver, with in-session controls
  and a Tor-route positive control.

Every T186 request runs in its own preserved tab and must reach a terminal
document bound to its unique label before a twelve-second observation
window (past Gecko's ten-second failover bound); an incomplete request is a
failure. `--mutation delayed-null` and `--mutation hung-proxy` (blocked-proxy
only) falsify the probe itself: a late `null` must be caught at the
destination and a never-answered request must fail as incomplete.

```sh
python3 tests/live-e2e/mullvad-browser-hardening/probe.py \
  --browser <mullvadbrowser binary> --driver <geckodriver> \
  --extension extension/dist/stargate-extension.zip \
  --only blocked-proxy --report-out target/runs/T186-blocked.json
```

The extension requires Gecko 153 or later; `descriptor-matrix` also runs
on older browsers because it installs only its own test extension.

## Private-window access and the profile baseline (`probe.py`; T188)

`--only private-access` applies the shipped `browser-profile/user.js`
(`--profile-template`) to every session and uses the same per-request tabs,
twelve-second observation and four surfaces as T186. Sessions install the
real package without private-window access unless a scenario grants it, as a
temporary about:debugging load does. It checks, with in-run controls:

- the baseline sink, moved to a live Unix SOCKS listener, receives every
  protected name by name (proxy-side DNS) while ICANN names bypass it;
- permanent private mode with no extension, and with the extension installed
  without access (its background never starts): `.onion`, `.onion.`,
  mixed-case and an unknown TLD fail closed on every surface; `.com` and a
  mixed-case subdomain load directly; the proxy prefs are not locked;
- ordinary windows without access: the extension's notification (title and
  text recorded as its alert window opens, with `alerts.useSystemBackend=false`),
  the popup's unprotected state, a blocked protected request, and a readable
  `proxy.settings` (Gecko requires private-browsing access only to set it);
- with access, in permanent private and in ordinary windows (observed after an
  extension reload, as after the about:addons toggle; a temporary install first
  starts once without the grant): Tor reaches the
  8881 catcher with the credential and no other surface, clearnet
  `{type:'direct'}` loads directly, `proxy.settings` is readable and no warning
  appears; with a changed `no_proxies_on` the baseline warning appears in the
  notification and popup;
- a `delayed-fallback` mutant whose router returns Direct for `.onion.` with
  the cancel layer disabled reaches the sink (calibrated under an ordinary
  proxy, where the same mutant reaches that proxy);
- recorded, not asserted: an emptied or garbled `network.proxy.socks`, and
  whether CIDR entries bypass a non-loopback IP literal.

Without the template file the sessions run today's ordinary-proxy
configuration, which is the red state.

```sh
python3 tests/live-e2e/mullvad-browser-hardening/probe.py \
  --browser <mullvadbrowser binary> --driver <geckodriver> \
  --extension extension/dist/stargate-extension.zip \
  --only private-access --report-out target/runs/T188-private-access.json
```

## Preserve / reset split

- **Preserve** (carry across runs): the test profile's hardened pref
  state (`network.trr.mode = 5`, etc.). The whole point is that this
  state is verified, then trusted until the next release-cadence run.
- **Reset** (re-create each run): `storage.local.hardening.lastAuditResult`
  in the test profile — the extension writes the latest audit result
  there; the test reads it fresh. Use a clean profile or clear the key
  before each run so a stale "ok" from a prior run cannot mask a
  regression.

## How to run

```sh
# Opt in (release-cadence; not on the hermetic PR path):
STARGATE_LIVE_E2E=1 MULLVAD_BROWSER_PROFILE=/path/to/test-profile \
  bash tests/live-e2e/mullvad-browser-hardening/run.sh
```

Without `STARGATE_LIVE_E2E=1`, `run.sh` prints SKIP and exits 0 (so a
casual invocation does not fail). With it set, missing preconditions
(browser binary, profile path) fail loudly, non-zero.

## Failure handling

A failure here is a **release blocker**, not a PR blocker (this test does
not run on the PR path). If the profile drifted (a pref flipped), fix the
profile and re-run. If the extension's runtime gate disagrees with the
profile pref (property 4 mismatch), that is a real bug in
`extension/background/hardening.js` (T055) — file a remediation ticket
with `remediates: T055` and do not tag the release.

## Governance note

This test is part of the T091 Constitution Principle III amendment
proposal. It is the concrete enforcement mechanism the amendment names
("externally verified precondition"). If T091 is rejected or materially
changed during the 7-day governance comment window, this test's scope is
revisited at the step-17 finish.
