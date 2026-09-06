// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// router.test.js — Principle-VII unit test for the extension's routing
// authority (`background/router.js`; T054). The router is the canonical
// implementation of the `.onion`→127.0.0.1:8881 rule (FR-001) and the
// consumer of the FR-004(b) fail-closed gate, so this suite is its
// executable spec: descriptor contract (FR-001/002/003 + the absent
// failoverTimeout decision), the fail-closed matrix (gate closed / token
// absent / FirstPartyError → direct, never a guessed username), and the
// background half of the T034c-pinned popup transport (per-tab decision
// cache written by `webRequest.onBeforeRequest`, answered via
// `runtime.onMessage` for `{type:'stargate:getRoute', tabId}` — `{route:
// 'tor'}` iff a confirmed Tor decision is cached; the wrong-positive
// guard: an onion tab routed while the gate is closed must read
// `unrouted`, never `tor`).
//
// Fidelity: the sandbox is the REAL shared MV2 background-page scope —
// `lib/firstparty.js` and `lib/storage.js` are loaded into the same
// context before `background/router.js`, so username behaviour is
// exercised against the real first-party module and the token mirror
// against the real storage wrapper, with only `browser` mocked. The
// loader hard-FAILS (never silently skips) when router.js is absent or
// off-surface: unlike the frozen tests-first suites (T034b/T034c/T034d)
// there is no downstream impl ticket to lift the gate — this suite ships
// in the same commit as the implementation, so RED (ENOENT) is the
// pre-impl state by construction.
//
// Surface pin (T034g doctrine): firstparty.js / storage.js /
// hardening.js / router.js all evaluate into ONE background-page global
// scope. router.js contributes ZERO new property globals — everything
// lives inside one IIFE; its surface is its browser registrations
// (`proxy.onRequest`, `webRequest.onBeforeRequest`, `runtime.onMessage`,
// `storage.onChanged`), not scope bindings.
//
// Node built-ins only; vm.runInNewContext loader (research.md §10) — no
// third-party deps, no package.json. Fixtures are syntactic only (32-hex
// token placeholders; v3-shaped onion labels — checksum validity is
// irrelevant to this contract, T034d fixture style).

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROUTER_PATH = path.join(__dirname, 'router.js');
const FIRSTPARTY_PATH = path.join(__dirname, '..', 'lib', 'firstparty.js');
const STORAGE_PATH = path.join(__dirname, '..', 'lib', 'storage.js');

// Canonical 32-lowercase-hex token placeholders (data-model.md §5 shape;
// syntactic only — never a real credential). Assembled with repeat() per
// the T052 storage.test.js fixture convention: a computed value keeps the
// pre-commit secret scanner (gitleaks generic-api-key) off placeholder
// literals, while every assertion still sees a full 32-hex string.
const TOKEN_A = '0f1e2d3c'.repeat(4);
const TOKEN_B = 'a1b2c3d4'.repeat(4);

// 56 base32 chars (a-z, 2-7) + `.onion` — v3-shaped addresses (T034c/
// T034d fixture style).
const ONION_A = 'abcd2345'.repeat(7) + '.onion';
const ONION_B = 'mnop6421'.repeat(7) + '.onion';

// Pinned protocol constant (T034c §Analysis finding 1).
const GET_ROUTE = 'stargate:getRoute';

// The shared background scope as the loader seeds it. firstparty.js adds
// `firstPartyDomain`, storage.js adds `StargateStorage`; router.js must
// add NOTHING beyond these (§Surface pin).
const SEEDED = ['URL', 'browser', 'console', 'hardeningOk'];
const LIB_GLOBALS = ['StargateStorage', 'firstPartyDomain'].sort();

function makeBrowser(state, recorded) {
  return {
    proxy: {
      onRequest: {
        addListener(fn) {
          recorded.proxy.push(fn);
        },
      },
    },
    webRequest: {
      onBeforeRequest: {
        addListener(fn, filter) {
          recorded.webRequest.push(fn);
          recorded.webRequestFilters.push(filter);
        },
      },
    },
    runtime: {
      onMessage: {
        addListener(fn) {
          recorded.message.push(fn);
        },
      },
    },
    storage: {
      local: {
        // Mirrors storage.js's read contract: the whole bag, `device` key
        // present iff configured. Read live off `state` so tests can move
        // the stored device between phases; `null` is the absent sentinel.
        get() {
          recorded.localGets.push(1);
          return Promise.resolve(
            state.device === null ? {} : { device: state.device }
          );
        },
      },
      onChanged: {
        addListener(fn) {
          recorded.onChanged.push(fn);
        },
      },
    },
  };
}

// Loads firstparty.js + storage.js + router.js into ONE fresh context —
// the real background-page script sequence (manifest M4 order minus
// hardening.js, whose `hardeningOk` flag is seeded directly). `device`
// uses an explicit `null`-means-absent sentinel: a destructuring default
// cannot distinguish "absent" from "explicitly undefined".
function loadRouter(options) {
  const {
    hardeningOk = false, // hardening.js's initial state: fail-closed until
                         // the first audit completes
    device = { name: 'test-device', bearerToken: TOKEN_A, tokenStoredAt: 1 },
  } = options || {};
  const recorded = {
    proxy: [],
    webRequest: [],
    webRequestFilters: [],
    message: [],
    onChanged: [],
    localGets: [],
  };
  const state = { device, hardeningOk };
  const sandbox = {
    URL,
    console,
    browser: makeBrowser(state, recorded),
    hardeningOk: state.hardeningOk,
  };
  vm.runInNewContext(fs.readFileSync(FIRSTPARTY_PATH, 'utf8'), sandbox, {
    filename: 'lib/firstparty.js',
  });
  vm.runInNewContext(fs.readFileSync(STORAGE_PATH, 'utf8'), sandbox, {
    filename: 'lib/storage.js',
  });
  vm.runInNewContext(fs.readFileSync(ROUTER_PATH, 'utf8'), sandbox, {
    filename: 'background/router.js',
  });
  return { sandbox, recorded, state };
}

// vm objects carry the sandbox context's prototype, so deepStrictEqual
// against a test-context fixture fails even on identical structure.
// Round-trip through JSON for structural comparison; `undefined` passes
// through (the responder's not-handled value).
function plain(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

// Realm-safe Promise check. The router's answers are built with the
// SANDBOX context's Promise constructor (the loader is a vm context —
// the real shared-scope fidelity), so `instanceof Promise` against this
// file's realm would false-negative on a correct implementation. The
// response-channel contract is "thenable or nothing", which this checks.
function isResponseChannel(value) {
  return (
    value !== null &&
    (typeof value === 'object' || typeof value === 'function') &&
    typeof value.then === 'function'
  );
}

// Surface conformance: exactly the two lib globals, nothing from router.js.
// Hard-fail with the T034g register — a silent re-skip here would let a
// global-leaking router ship ungated.
function requireConformance(sandbox) {
  const newGlobals = Object.keys(sandbox)
    .filter((k) => !SEEDED.includes(k))
    .sort();
  assert.deepStrictEqual(
    newGlobals, LIB_GLOBALS,
    'pinned surface violated: router.js must contribute ZERO new globals ' +
      'to the shared background-page scope (T034g doctrine; expected ' +
      `exactly ${JSON.stringify(LIB_GLOBALS)} beyond the seed). Got: ` +
      JSON.stringify(newGlobals)
  );
}

// The canonical hardened-load: gate open, token mirrored. Returns the
// registered listeners by name for driving requests.
function loadHardenedTokened() {
  const loaded = loadRouter({ hardeningOk: true });
  requireConformance(loaded.sandbox);
  assert.strictEqual(
    loaded.recorded.proxy.length, 1,
    'router.js must register exactly one proxy.onRequest listener at ' +
      'evaluation'
  );
  assert.strictEqual(
    loaded.recorded.webRequest.length, 1,
    'router.js must register exactly one webRequest.onBeforeRequest ' +
      'listener at evaluation (the T034c cache writer)'
  );
  assert.strictEqual(
    loaded.recorded.message.length, 1,
    'router.js must register exactly one runtime.onMessage responder at ' +
      'evaluation'
  );
  return {
    onRequest: loaded.recorded.proxy[0],
    onBeforeRequest: loaded.recorded.webRequest[0],
    onMessage: loaded.recorded.message[0],
    ...loaded,
  };
}

// Let the load-time token-mirror promise settle (bounded macrotask turns;
// deterministic for promise-only chains — T034b drain idiom).
async function drain(turns = 10) {
  for (let i = 0; i < turns; i += 1) {
    await new Promise(setImmediate);
  }
}

function mainFrame(url, extra) {
  return { url, type: 'main_frame', tabId: 7, ...extra };
}

// ---------------------------------------------------------------------------
// Descriptor contract (FR-001/002/003 + tasks.md T054 decisions)
// ---------------------------------------------------------------------------

test('onionTopLevelNavigationReturnsCanonicalSocksDescriptor', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const descriptor = onRequest(mainFrame(`https://${ONION_A}/page`));
  assert.deepStrictEqual(
    plain(descriptor),
    {
      type: 'socks',
      host: '127.0.0.1',
      port: 8881,
      username: ONION_A,
      password: TOKEN_A,
      proxyDNS: true,
    },
    'FR-001/002/003: the .onion descriptor is socks/127.0.0.1:8881 with ' +
      'the full onion host as username, the bearer token as password, and ' +
      'proxyDNS true (SOCKS5h)'
  );
  assert.strictEqual(
    'failoverTimeout' in descriptor, false,
    'tasks.md T054 decision: failoverTimeout is intentionally NOT set — ' +
      'Firefox default applies; the key must be absent, not merely default'
  );
});

test('distinctOnionFirstPartiesGetDistinctUsernames', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const a = onRequest(mainFrame(`https://${ONION_A}/`));
  const b = onRequest(mainFrame(`https://${ONION_B}/`));
  assert.strictEqual(a.username, ONION_A, 'onion hosts are not reduced');
  assert.strictEqual(b.username, ONION_B, 'onion hosts are not reduced');
  assert.notStrictEqual(
    a.username, b.username,
    'FR-002/Constitution III: distinct first parties MUST isolate — ' +
      'distinct usernames are the stream-isolation signal Tor acts on'
  );
});

test('onionSubresourceUsernameFollowsGoverningDocument', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  // Subresource of an onion page: governing URL is the parent document,
  // username is the parent's onion address (FR-002 .onion rule).
  const sameOrigin = onRequest(
    mainFrame(`https://${ONION_A}/img.png`, {
      documentUrl: `https://${ONION_A}/page`,
    })
  );
  assert.strictEqual(sameOrigin.username, ONION_A);
  assert.strictEqual(sameOrigin.type, 'socks');

  // An onion subresource requested BY a clearnet page still routes via
  // Tor (FR-001 keys on the request host — the bytes are going to an
  // onion service), with the governing document's first party as the
  // username (FR-002 precedence: documentUrl wins).
  const crossOrigin = onRequest(
    mainFrame(`https://${ONION_B}/pixel.gif`, {
      documentUrl: 'https://example.com/page',
    })
  );
  assert.strictEqual(crossOrigin.username, 'example.com');
  assert.strictEqual(crossOrigin.type, 'socks');
});

test('clearnetRequestsAreDirectAndNeverCarryTheTokenOrPort', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const descriptor = onRequest(
    mainFrame('https://example.com/page', {
      documentUrl: 'https://example.com/',
    })
  );
  assert.deepStrictEqual(
    plain(descriptor), { type: 'direct' },
    'FR-001 scope: non-.onion hosts get no proxy in this feature'
  );
  const leak = JSON.stringify(descriptor);
  assert.ok(
    !leak.includes(TOKEN_A) && !leak.includes('8881') && !leak.includes('socks'),
    'the direct descriptor must carry no credential and no port-8881 ' +
      'proxy surface'
  );
});

test('trailingDotFqdnOnionHostStillRoutesAsOnion', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const descriptor = onRequest(mainFrame(`https://${ONION_A}./page`));
  assert.strictEqual(
    descriptor.type, 'socks',
    'the FQDN-dot form of an onion host must not evade the FR-001 ' +
      'classification (firstparty.js strips one trailing dot; the router ' +
      'mirrors that normalization)'
  );
  assert.strictEqual(
    descriptor.username, ONION_A,
    'the username is the dot-stripped onion host — no degenerate label'
  );
});

// ---------------------------------------------------------------------------
// Fail-closed matrix (FR-004(b) as amended by T091; Constitution III)
// ---------------------------------------------------------------------------

test('closedHardeningGateFailsClosedAndRecordsUnrouted', async () => {
  // Default seed: hardeningOk = false (hardening.js initial state until
  // its startup audit completes; also the WebRTC-enabled state).
  const { onRequest, onBeforeRequest, onMessage } = await (async () => {
    const loaded = loadRouter({ hardeningOk: false });
    await drain();
    requireConformance(loaded.sandbox);
    return {
      onRequest: loaded.recorded.proxy[0],
      onBeforeRequest: loaded.recorded.webRequest[0],
      onMessage: loaded.recorded.message[0],
    };
  })();
  const details = mainFrame(`https://${ONION_A}/page`);
  const descriptor = onRequest(details);
  assert.deepStrictEqual(
    plain(descriptor), { type: 'direct' },
    'FR-004(b): no SOCKS descriptor leaves the module while the gate is ' +
      'closed — the request must not route through port 8881'
  );
  assert.strictEqual(
    JSON.stringify(descriptor).includes(TOKEN_A), false,
    'the blocked descriptor carries no credential'
  );
  // The T034c wrong-positive guard: the tab's cached decision must read
  // unrouted, so the popup renders its fail-closed label — never
  // `Route: Tor` for an onion tab routed while the gate was closed.
  const webRequestResult = onBeforeRequest(details);
  assert.ok(
    webRequestResult === undefined ||
      (webRequestResult && webRequestResult.cancel === undefined),
    'the cache-writing listener must not cancel or redirect'
  );
  const blockedReply = onMessage({ type: GET_ROUTE, tabId: 7 });
  assert.ok(
    isResponseChannel(blockedReply),
    'owned messages must be answered via the response channel (a ' +
      'Promise return) — Firefox discards plain synchronous returns ' +
      '(round-1 review Major)'
  );
  assert.deepStrictEqual(
    plain(await blockedReply), { route: 'unrouted' },
    'an onion tab behind a closed gate reads unrouted — the popup ' +
      'wrong-positive case (d) forbids'
  );
});

test('missingOrEmptyTokenFailsClosed', async () => {
  const noDevice = loadRouter({ hardeningOk: true, device: null });
  await drain();
  assert.deepStrictEqual(
    plain(noDevice.recorded.proxy[0](mainFrame(`https://${ONION_A}/`))),
    { type: 'direct' },
    'FR-002: without a bearer token the password clause cannot be ' +
      'satisfied — routing to 8881 would violate FR-002, so fail closed'
  );
  // The cache write must agree with the descriptor: fire the
  // cache-writing listener for the tab, then ask via the pinned protocol.
  noDevice.recorded.webRequest[0](mainFrame(`https://${ONION_A}/`));
  const blockedReply = noDevice.recorded.message[0]({
    type: GET_ROUTE,
    tabId: 7,
  });
  assert.ok(
    isResponseChannel(blockedReply),
    'owned messages must be answered via the response channel (a ' +
      'Promise return) — Firefox discards plain synchronous returns'
  );
  assert.deepStrictEqual(
    plain(await blockedReply),
    { route: 'unrouted' },
    'and the tab reads unrouted, not tor'
  );

  const emptyToken = loadRouter({
    hardeningOk: true,
    device: { name: 'd', bearerToken: '', tokenStoredAt: 1 },
  });
  await drain();
  assert.deepStrictEqual(
    plain(emptyToken.recorded.proxy[0](mainFrame(`https://${ONION_A}/`))),
    { type: 'direct' },
    'an empty-string token is no token — presence means a non-empty string'
  );
});

test('firstPartyErrorFailsClosedWithoutGuessedUsername', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  // Present-but-unparseable governing URL (T034d sentinel contract): the
  // router must surface the failure as a DIRECT decision — never swallow
  // the sentinel into a guessed, empty, or shared username (the one-
  // routable-string collapse T034d finding 3 forbids).
  const descriptor = onRequest(
    mainFrame(`https://${ONION_A}/x`, { documentUrl: 'not a url' })
  );
  assert.deepStrictEqual(plain(descriptor), { type: 'direct' });
  assert.strictEqual(
    JSON.stringify(descriptor).includes('username'), false,
    'no username field of any value may accompany a FirstPartyError ' +
      'fail-closed decision'
  );
});

// ---------------------------------------------------------------------------
// T034c protocol: per-tab cache + getRoute responder
// ---------------------------------------------------------------------------

test('getRouteResponderPinnedSemantics', async () => {
  const { onBeforeRequest, onMessage } = loadHardenedTokened();
  await drain();

  onBeforeRequest(mainFrame(`https://${ONION_A}/`, { tabId: 3 }));
  onBeforeRequest(
    mainFrame('https://example.com/', {
      tabId: 4,
      documentUrl: 'https://example.com/',
    })
  );
  // Non-tab request (tabId -1: devtools/service-worker/extension traffic)
  // has no indicator to feed and must not poison the cache.
  onBeforeRequest(mainFrame(`https://${ONION_B}/`, { tabId: -1 }));

  const torReply = onMessage({ type: GET_ROUTE, tabId: 3 });
  assert.ok(
    isResponseChannel(torReply),
    'confirmed Tor decisions must be answered via the response channel ' +
      '(a Promise return) — Firefox discards plain synchronous returns ' +
      '("The listener function can return either a Boolean or a ' +
      'Promise", MDN; round-1 review Major: the plain-return mutant left ' +
      'the suite green while the popup transport was inert on the platform)'
  );
  assert.deepStrictEqual(
    plain(await torReply), { route: 'tor' },
    'confirmed Tor decision → {route:"tor"} (the iff pin)'
  );
  const unroutedReply = onMessage({ type: GET_ROUTE, tabId: 4 });
  assert.ok(isResponseChannel(unroutedReply), 'owned messages get the channel');
  assert.deepStrictEqual(
    plain(await unroutedReply), { route: 'unrouted' },
    'recorded non-Tor decision → {route:"unrouted"} (T034c case (b))'
  );
  const unknownReply = onMessage({ type: GET_ROUTE, tabId: 99 });
  assert.ok(
    isResponseChannel(unknownReply),
    'an owned query for an unknown tab still owns the channel — it ' +
      'resolves nothing meaningful rather than declining to answer'
  );
  assert.strictEqual(
    await unknownReply, undefined,
    'unknown tab → nothing meaningful (the cold-start state of T034c ' +
      'case (d))'
  );
  assert.strictEqual(
    onMessage({ type: GET_ROUTE, tabId: -1 }), undefined,
    'non-tab requests never enter the per-tab cache'
  );
  assert.strictEqual(
    onMessage({ type: 'some-other-extension-message', tabId: 3 }), undefined,
    'foreign message shapes are not answered by this responder (other ' +
      'listeners may handle them)'
  );
  assert.strictEqual(
    onMessage({ type: GET_ROUTE, tabId: '3' }), undefined,
    'a non-number tabId never matches a cache key'
  );
  assert.strictEqual(onMessage(null), undefined, 'null message is inert');
});

// ---------------------------------------------------------------------------
// Token mirror (storage.onChanged)
// ---------------------------------------------------------------------------

test('storageOnChangedRefreshesMirroredToken', async () => {
  const loaded = loadRouter({ hardeningOk: true });
  await drain();
  const onRequest = loaded.recorded.proxy[0];
  const onChanged = loaded.recorded.onChanged;
  assert.strictEqual(
    loaded.recorded.localGets.length >= 1, true,
    'the token mirror is read once at script evaluation (hardening.js ' +
      'load-time-async precedent)'
  );

  // Token rotation: the next descriptor carries the new credential.
  loaded.state.device = {
    name: 'test-device',
    bearerToken: TOKEN_B,
    tokenStoredAt: 2,
  };
  onChanged[0]({ device: { newValue: loaded.state.device } }, 'local');
  await drain();
  assert.strictEqual(
    onRequest(mainFrame(`https://${ONION_A}/`)).password, TOKEN_B,
    'a storage.onChanged event for the device key must refresh the ' +
      'mirrored token — descriptors must never serve a stale credential'
  );

  // Device removal: the mirror drops to absent → fail closed.
  loaded.state.device = null;
  onChanged[0]({ device: { oldValue: { bearerToken: TOKEN_B } } }, 'local');
  await drain();
  assert.deepStrictEqual(
    plain(onRequest(mainFrame(`https://${ONION_A}/`))), { type: 'direct' },
    'device removal fail-closes the router'
  );

  // Unrelated storage keys must not touch the mirror.
  loaded.state.device = { name: 'd', bearerToken: TOKEN_B, tokenStoredAt: 3 };
  onChanged[0]({ hardening: { newValue: {} } }, 'local');
  await drain();
  assert.deepStrictEqual(
    plain(onRequest(mainFrame(`https://${ONION_A}/`))), { type: 'direct' },
    'a non-device change event must not resurrect the mirror from ' +
      'current storage state it was not refreshed against'
  );
});

// ---------------------------------------------------------------------------
// Surface (T034g register) — pinned via requireConformance on every load
// above; the standalone case documents the pin for the falsification
// battery.
// ---------------------------------------------------------------------------

test('routerContributesZeroNewGlobalsToTheSharedScope', () => {
  const { sandbox } = loadRouter({ hardeningOk: true });
  const newGlobals = Object.keys(sandbox)
    .filter((k) => !SEEDED.includes(k))
    .sort();
  assert.deepStrictEqual(
    newGlobals, LIB_GLOBALS,
    'firstparty.js contributes firstPartyDomain, storage.js contributes ' +
      'StargateStorage, router.js contributes NOTHING — an extra ' +
      'top-level binding is a namespace-collision surface on the one ' +
      'shared MV2 background scope (T034g)'
  );
});
