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
// (`proxy.onRequest`, `webRequest.onBeforeRequest`, `webNavigation.onCommitted`,
// `tabs.onRemoved`, `runtime.onMessage`, `storage.onChanged`), not scope bindings.
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
const { webcrypto } = require('node:crypto');
const { TextEncoder } = require('node:util');

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
const PROFILE_A = '11'.repeat(32);
const PROFILE_B = '22'.repeat(32);
// Independently derived with Python's standard-library HMAC implementation;
// the exact command and inputs are pinned in foundation-boundaries.md.
const ONION_A_USERNAME =
  'sg1:1940cde7068246610f120ee0926ad88113942aa2e83d71ba649deab843077a06';

// 56 base32 chars (a-z, 2-7) + `.onion` — v3-shaped addresses (T034c/
// T034d fixture style).
const ONION_A = 'abcd2345'.repeat(7) + '.onion';
const ONION_B = 'mnop6421'.repeat(7) + '.onion';

// Pinned protocol constant (T034c §Analysis finding 1).
const GET_ROUTE = 'stargate:getRoute';

// The shared background scope as the loader seeds it. firstparty.js adds
// `firstPartyDomain`, storage.js adds `StargateStorage`; router.js must
// add NOTHING beyond these (§Surface pin).
const SEEDED = [
  'TextEncoder', 'URL', 'browser', 'console', 'crypto', 'hardeningOk',
];
const LIB_GLOBALS = [
  'StargateStorage', 'firstPartyDomain',
].sort();

function nativeRegistrableDomain(host) {
  const labels = host.split('.');
  if (host === 'co.uk') return null;
  if (host.endsWith('.co.uk') && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  if (host.endsWith('.github.io') && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  if (host.endsWith('.com') && labels.length >= 2) {
    return labels.slice(-2).join('.');
  }
  return null;
}

function makeBrowser(state, recorded) {
  return {
    publicSuffix: {
      getDomain(host) {
        recorded.publicSuffix.push(host);
        return nativeRegistrableDomain(host);
      },
    },
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
    webNavigation: {
      onCommitted: {
        addListener(fn) {
          recorded.committed.push(fn);
        },
      },
    },
    tabs: {
      onRemoved: {
        addListener(fn) {
          recorded.tabRemoved.push(fn);
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
        get(key) {
          recorded.localGets.push(1);
          if (key === 'device' && state.deviceGet !== null) {
            return state.deviceGet();
          }
          const bag = {};
          if (state.device !== null) bag.device = state.device;
          if (state.isolationProfileId !== null) {
            bag.isolationProfileId = state.isolationProfileId;
          }
          return Promise.resolve(bag);
        },
        set(values) {
          recorded.localSets.push(plain(values));
          if (state.localSetError) return Promise.reject(state.localSetError);
          if ('isolationProfileId' in values) {
            state.isolationProfileId = values.isolationProfileId;
          }
          return Promise.resolve();
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
    isolationProfileId = PROFILE_A,
    localSetError = null,
    deviceGet = null,
    crypto = null,
  } = options || {};
  const recorded = {
    proxy: [],
    webRequest: [],
    webRequestFilters: [],
    message: [],
    onChanged: [],
    localGets: [],
    localSets: [],
    committed: [],
    tabRemoved: [],
    publicSuffix: [],
  };
  const state = {
    device, hardeningOk, isolationProfileId, localSetError, deviceGet,
  };
  const cryptoImpl = crypto || {
    subtle: webcrypto.subtle,
    getRandomValues(values) {
      values.fill(0x33);
      return values;
    },
  };
  const sandbox = {
    TextEncoder,
    URL,
    console,
    crypto: cryptoImpl,
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
  assert.strictEqual(
    loaded.recorded.committed.length, 1,
    'router.js must register one committed-navigation context listener'
  );
  return {
    onRequest: loaded.recorded.proxy[0],
    onBeforeRequest: loaded.recorded.webRequest[0],
    onMessage: loaded.recorded.message[0],
    onCommitted: loaded.recorded.committed[0],
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

async function waitForCachedRoute(onMessage, tabId, route) {
  let reply;
  for (let turn = 0; turn < 100; turn += 1) {
    reply = await onMessage({ type: GET_ROUTE, tabId });
    if (reply && reply.route === route) return reply;
    await drain(1);
  }
  return reply;
}

function mainFrame(url, extra) {
  return {
    url,
    type: 'main_frame',
    frameId: 0,
    parentFrameId: -1,
    tabId: 7,
    incognito: false,
    cookieStoreId: 'firefox-default',
    documentId: 'top-document-7',
    ...extra,
  };
}

function subresource(url, documentUrl, extra) {
  return {
    url,
    documentUrl,
    type: 'image',
    frameId: 0,
    parentFrameId: -1,
    tabId: 7,
    incognito: false,
    cookieStoreId: 'firefox-default',
    documentId: 'top-document-7',
    ...extra,
  };
}

function assertNoRoutableIdentity(descriptor, message) {
  assert.notStrictEqual(descriptor && descriptor.type, 'socks', message);
  assert.strictEqual(
    JSON.stringify(descriptor || {}).includes('username'),
    false,
    message + ' (no username)'
  );
  assert.strictEqual(
    JSON.stringify(descriptor || {}).includes(TOKEN_A),
    false,
    message + ' (no bearer)'
  );
}

// ---------------------------------------------------------------------------
// Descriptor contract (FR-001/002/003 + tasks.md T054 decisions)
// ---------------------------------------------------------------------------

test('onionTopLevelNavigationReturnsCanonicalSocksDescriptor', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const descriptor = await onRequest(mainFrame(`https://${ONION_A}/page`));
  assert.deepStrictEqual(
    plain(descriptor),
    {
      type: 'socks',
      host: '127.0.0.1',
      port: 8881,
      username: ONION_A_USERNAME,
      password: TOKEN_A,
      proxyDNS: true,
    },
    'FR-001/002/003: the .onion descriptor is socks/127.0.0.1:8881 with ' +
      'the fixed-vector opaque identity as username, the bearer token as password, and ' +
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
  const a = await onRequest(mainFrame(`https://${ONION_A}/`));
  const b = await onRequest(mainFrame(`https://${ONION_B}/`));
  assert.match(a.username, /^sg1:[0-9a-f]{64}$/);
  assert.match(b.username, /^sg1:[0-9a-f]{64}$/);
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
  const sameOrigin = await onRequest(
    subresource(
      `https://${ONION_A}/img.png`,
      `https://${ONION_A}/page`,
      { documentId: 'onion-document-a' }
    )
  );
  assert.strictEqual(sameOrigin.username, ONION_A_USERNAME);
  assert.strictEqual(sameOrigin.type, 'socks');

  // An onion subresource requested BY a clearnet page still routes via
  // Tor (FR-001 keys on the request host — the bytes are going to an
  // onion service), with the governing document's first party as the
  // username (FR-002 precedence: documentUrl wins).
  const crossOrigin = await onRequest(
    subresource(
      `https://${ONION_B}/pixel.gif`,
      'https://example.com/page',
      { documentId: 'clearnet-document-a' }
    )
  );
  assert.match(crossOrigin.username, /^sg1:[0-9a-f]{64}$/);
  assert.notStrictEqual(crossOrigin.username, ONION_A_USERNAME);
  assert.strictEqual(crossOrigin.type, 'socks');
});

test('sameOnionDestinationSeparatesPublicAndPrivateSuffixSites', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();

  async function usernameFor(documentUrl, documentId) {
    const descriptor = await onRequest({
      url: `https://${ONION_A}/same-target.gif`,
      documentUrl,
      type: 'image',
      frameId: 0,
      parentFrameId: -1,
      tabId: 7,
      incognito: false,
      cookieStoreId: 'firefox-default',
      documentId,
    });
    assert.strictEqual(descriptor.type, 'socks');
    return descriptor.username;
  }

  const aliceUK = await usernameFor('https://alice.co.uk/page', 'alice-uk');
  const bobUK = await usernameFor('https://bob.co.uk/page', 'bob-uk');
  assert.notStrictEqual(
    aliceUK,
    bobUK,
    'same onion destination under distinct co.uk registrable sites must ' +
      'produce distinct Tor isolation usernames (T136/M3)'
  );

  const alicePages = await usernameFor(
    'https://alice.github.io/page', 'alice-pages'
  );
  const bobPages = await usernameFor(
    'https://bob.github.io/page', 'bob-pages'
  );
  assert.notStrictEqual(
    alicePages,
    bobPages,
    'the PRIVATE github.io suffix must separate tenant sites for one ' +
      'onion destination (T136/M3)'
  );
});

test('usernameVectorIsBoundedOpaqueAndStableForOnePartition', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const first = await onRequest(mainFrame(`https://${ONION_A}/one`));
  const second = await onRequest(mainFrame(`http://${ONION_A}:80/two`));

  assert.strictEqual(first.username, ONION_A_USERNAME);
  assert.strictEqual(second.username, ONION_A_USERNAME);
  assert.strictEqual(first.username.length, 68, 'RFC 1929 username is 68 bytes');
  assert.ok(!first.username.includes(TOKEN_A), 'username excludes bearer bytes');
  assert.ok(!first.username.includes(ONION_A), 'username excludes literal site bytes');
});

test('deviceProfilePrivateAndContainerInputsSeparatePartitions', async () => {
  const a = loadRouter({ hardeningOk: true });
  const otherDevice = loadRouter({
    hardeningOk: true,
    device: { name: 'other', bearerToken: TOKEN_B, tokenStoredAt: 1 },
  });
  const otherProfile = loadRouter({
    hardeningOk: true,
    isolationProfileId: PROFILE_B,
  });
  await drain();

  const normal = await a.recorded.proxy[0](mainFrame(`https://${ONION_A}/`));
  const device = await otherDevice.recorded.proxy[0](
    mainFrame(`https://${ONION_A}/`)
  );
  const profile = await otherProfile.recorded.proxy[0](
    mainFrame(`https://${ONION_A}/`)
  );
  const privateMode = await a.recorded.proxy[0](
    mainFrame(`https://${ONION_A}/`, {
      incognito: true,
      cookieStoreId: 'firefox-private',
    })
  );
  const container = await a.recorded.proxy[0](
    mainFrame(`https://${ONION_A}/`, { cookieStoreId: 'firefox-container-1' })
  );

  const usernames = [normal, device, profile, privateMode, container]
    .map((descriptor) => descriptor.username);
  assert.strictEqual(new Set(usernames).size, usernames.length);
  for (const username of usernames) assert.match(username, /^sg1:[0-9a-f]{64}$/);
});

test('profileIdentityInitializesOnceAndInvalidStateIsUnavailable', async () => {
  const firstInstall = loadRouter({
    hardeningOk: true,
    isolationProfileId: null,
  });
  const onRequest = firstInstall.recorded.proxy[0];
  const [one, two] = await Promise.all([
    onRequest(mainFrame(`https://${ONION_A}/one`)),
    onRequest(mainFrame(`https://${ONION_A}/two`)),
  ]);
  assert.strictEqual(one.username, two.username);
  assert.deepStrictEqual(firstInstall.recorded.localSets, [
    { isolationProfileId: '33'.repeat(32) },
  ]);

  for (const loaded of [
    loadRouter({ hardeningOk: true, isolationProfileId: 'not-a-profile-id' }),
    loadRouter({
      hardeningOk: true,
      isolationProfileId: null,
      localSetError: new Error('synthetic storage failure'),
    }),
  ]) {
    const descriptor = await loaded.recorded.proxy[0](
      mainFrame(`https://${ONION_A}/`)
    );
    assertNoRoutableIdentity(
      descriptor,
      'malformed or unwritable browser-profile state is unavailable'
    );
  }
});

test('nativeSuffixOrCryptoFailureHasNoRoutableIdentity', async () => {
  const suffixFailure = loadRouter({ hardeningOk: true });
  suffixFailure.sandbox.browser.publicSuffix.getDomain = () => {
    throw new Error('synthetic native suffix failure');
  };
  assertNoRoutableIdentity(
    await suffixFailure.recorded.proxy[0](mainFrame(`https://${ONION_A}/`, {
      type: 'image',
      documentUrl: 'https://www.example.com/page',
    })),
    'native suffix failure is identity-unavailable'
  );

  const cryptoFailure = loadRouter({
    hardeningOk: true,
    crypto: {
      getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
      subtle: {
        importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
        sign() {
          return Promise.reject(new Error('synthetic HMAC failure'));
        },
      },
    },
  });
  assertNoRoutableIdentity(
    await cryptoFailure.recorded.proxy[0](mainFrame(`https://${ONION_A}/`)),
    'HMAC failure is identity-unavailable'
  );
});

test('documentBoundContextGovernsFramesWorkersAndRedirects', async () => {
  const loaded = loadHardenedTokened();
  await drain();
  const { onRequest, onCommitted } = loaded;
  onCommitted({
    tabId: 9, frameId: 0, url: 'https://alice.co.uk/page',
    documentId: 'top-alice',
  });
  onCommitted({
    tabId: 9, frameId: 4, url: 'https://third-party-frame.example/page',
    documentId: 'frame-alice', parentDocumentId: 'top-alice',
  });

  const top = await onRequest(subresource(
    `https://${ONION_A}/top.gif`,
    'https://alice.co.uk/page',
    { tabId: 9, documentId: 'top-alice' }
  ));
  const nested = await onRequest(subresource(
    `https://${ONION_A}/nested.gif`,
    'https://third-party-frame.example/page',
    {
      tabId: 9, frameId: 4, parentFrameId: 0,
      documentId: 'frame-alice', parentDocumentId: 'top-alice',
    }
  ));
  const worker = await onRequest({
    url: `https://${ONION_A}/worker-fetch`,
    type: 'xmlhttprequest',
    frameId: 4,
    parentFrameId: 0,
    tabId: 9,
    incognito: false,
    cookieStoreId: 'firefox-default',
    documentId: 'frame-alice',
    parentDocumentId: 'top-alice',
  });
  assert.strictEqual(nested.username, top.username);
  assert.strictEqual(worker.username, top.username);

  const redirectedMain = await onRequest(mainFrame(
    `https://${ONION_B}/redirect-target`, {
      tabId: 9,
      documentId: 'top-bob-pending',
      documentUrl: 'https://alice.co.uk/stale-document-metadata',
      originUrl: 'https://alice.co.uk/stale-origin-metadata',
    }
  ));
  const redirectedControl = await onRequest(mainFrame(
    `https://${ONION_B}/clean-navigation`, {
      tabId: 10, documentId: 'top-bob-control',
    }
  ));
  assert.strictEqual(redirectedMain.type, 'socks');
  assert.strictEqual(redirectedControl.type, 'socks');
  assert.strictEqual(redirectedMain.username, redirectedControl.username);
  assert.notStrictEqual(redirectedMain.username, top.username);
  const afterUncommittedRedirect = await onRequest(subresource(
    `https://${ONION_A}/still-old-document.gif`,
    'https://alice.co.uk/page',
    { tabId: 9, documentId: 'top-alice' }
  ));
  assert.strictEqual(afterUncommittedRedirect.username, top.username);
});

test('retiredTopDocumentCannotBeReboundAfterReplacement', async () => {
  let releaseDevice;
  const deviceRead = new Promise((resolve) => {
    releaseDevice = () => resolve({
      device: {
        name: 'test-device', bearerToken: TOKEN_A, tokenStoredAt: 1,
      },
    });
  });
  const loaded = loadRouter({
    hardeningOk: true,
    deviceGet() {
      return deviceRead;
    },
  });
  await drain();
  const onRequest = loaded.recorded.proxy[0];
  const onCommitted = loaded.recorded.committed[0];
  onCommitted({
    tabId: 13, frameId: 0, url: 'https://alice.co.uk/',
    documentId: 'old-top',
  });
  const pending = onRequest(subresource(
    `https://${ONION_A}/delayed`,
    'https://alice.co.uk/',
    { tabId: 13, documentId: 'old-top' }
  ));
  onCommitted({
    tabId: 13, frameId: 0, url: 'https://bob.co.uk/',
    documentId: 'new-top',
  });
  releaseDevice();

  assertNoRoutableIdentity(
    await pending,
    'a request delayed before context resolution must not resurrect a ' +
      'document retired by navigation'
  );
  assertNoRoutableIdentity(
    await onRequest(subresource(
      `https://${ONION_A}/late-old`,
      'https://alice.co.uk/',
      { tabId: 13, documentId: 'old-top' }
    )),
    'a late request must not rebind a retired top-level document'
  );
  assert.strictEqual(
    (await onRequest(subresource(
      `https://${ONION_A}/current`,
      'https://bob.co.uk/',
      { tabId: 13, documentId: 'new-top' }
    ))).type,
    'socks',
    'the current committed document remains routable'
  );
  loaded.recorded.tabRemoved[0](13);
  assert.strictEqual(
    (await onRequest(subresource(
      `https://${ONION_A}/reused-tab`,
      'https://alice.co.uk/',
      { tabId: 13, documentId: 'reused-tab-top' }
    ))).type,
    'socks',
    'tab teardown must release the current-document guard before ID reuse'
  );
});

test('documentReplacementInvalidatesInFlightNestedContext', async () => {
  let releaseSign;
  const delayedCrypto = {
    getRandomValues(values) {
      values.fill(0x44);
      return values;
    },
    subtle: {
      importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
      sign(...args) {
        return new Promise((resolve, reject) => {
          releaseSign = () => webcrypto.subtle.sign(...args).then(resolve, reject);
        });
      },
    },
  };
  const loaded = loadRouter({ hardeningOk: true, crypto: delayedCrypto });
  await drain();
  loaded.recorded.committed[0]({
    tabId: 12, frameId: 0, url: 'https://alice.co.uk/',
    documentId: 'old-top',
  });
  loaded.recorded.committed[0]({
    tabId: 12, frameId: 2, url: 'https://frame.example/',
    documentId: 'old-frame', parentDocumentId: 'old-top',
  });
  const pending = loaded.recorded.proxy[0]({
    url: `https://${ONION_A}/nested`, type: 'image', frameId: 2,
    parentFrameId: 0, tabId: 12, incognito: false,
    cookieStoreId: 'firefox-default', documentId: 'old-frame',
    parentDocumentId: 'old-top',
  });
  while (!releaseSign) await drain(1);
  loaded.recorded.committed[0]({
    tabId: 12, frameId: 0, url: 'https://bob.co.uk/',
    documentId: 'new-top',
  });
  releaseSign();
  assertNoRoutableIdentity(
    await pending,
    'a navigation that retires a document must invalidate its pending HMAC'
  );
});

test('unknownDetachedOpaqueAndOriginOnlyContextsHaveNoIdentity', async () => {
  const loaded = loadHardenedTokened();
  await drain();
  const onRequest = loaded.onRequest;
  const cases = [
    {
      url: `https://${ONION_A}/nested`, type: 'image', frameId: 3,
      parentFrameId: 0, tabId: 99, incognito: false,
      cookieStoreId: 'firefox-default', documentId: 'unknown-frame',
      parentDocumentId: 'unknown-top',
    },
    {
      url: `https://${ONION_A}/worker`, type: 'xmlhttprequest', frameId: -1,
      parentFrameId: -1, tabId: -1, incognito: false,
      cookieStoreId: 'firefox-default', documentId: 'detached-worker',
    },
    {
      url: `https://${ONION_A}/css-image`, type: 'image', frameId: 0,
      parentFrameId: -1, tabId: 98, incognito: false,
      cookieStoreId: 'firefox-default', documentId: 'origin-only',
      originUrl: 'https://cdn.example/style.css',
    },
  ];
  loaded.onCommitted({
    tabId: 10, frameId: 0, url: 'about:blank', documentId: 'opaque-top',
  });
  cases.push({
    url: `https://${ONION_A}/opaque`, type: 'image', frameId: 2,
    parentFrameId: 0, tabId: 10, incognito: false,
    cookieStoreId: 'firefox-default', documentUrl: 'about:blank',
    documentId: 'opaque-frame', parentDocumentId: 'opaque-top',
  });

  for (const details of cases) {
    assertNoRoutableIdentity(
      await onRequest(details),
      'untrustworthy top-level context must not use the onion destination'
    );
  }
});

test('tokenRotationInvalidatesAnInFlightHmacCompletion', async () => {
  let releaseSign;
  const delayedCrypto = {
    getRandomValues(values) {
      values.fill(0x44);
      return values;
    },
    subtle: {
      importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
      sign(...args) {
        return new Promise((resolve, reject) => {
          releaseSign = () => webcrypto.subtle.sign(...args).then(resolve, reject);
        });
      },
    },
  };
  const loaded = loadRouter({ hardeningOk: true, crypto: delayedCrypto });
  await drain();
  const pending = loaded.recorded.proxy[0](mainFrame(`https://${ONION_A}/`));
  while (!releaseSign) await drain(1);

  loaded.state.device = {
    name: 'rotated', bearerToken: TOKEN_B, tokenStoredAt: 2,
  };
  loaded.recorded.onChanged[0](
    { device: { newValue: loaded.state.device } },
    'local'
  );
  await drain();
  releaseSign();
  assertNoRoutableIdentity(
    await pending,
    'a HMAC completed under a stale token generation must not route'
  );
});

test('synchronousKeyImportFailureDuringRotationFailsClosed', async () => {
  let imports = 0;
  const failingRotationCrypto = {
    getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
    subtle: {
      importKey(...args) {
        imports += 1;
        if (imports > 1) throw new Error('synthetic synchronous import failure');
        return webcrypto.subtle.importKey(...args);
      },
      sign: webcrypto.subtle.sign.bind(webcrypto.subtle),
    },
  };
  const loaded = loadRouter({ hardeningOk: true, crypto: failingRotationCrypto });
  await drain();
  assert.strictEqual(
    (await loaded.recorded.proxy[0](mainFrame(`https://${ONION_A}/`))).type,
    'socks'
  );
  const rotated = {
    name: 'rotated', bearerToken: TOKEN_B, tokenStoredAt: 2,
  };
  assert.doesNotThrow(() => loaded.recorded.onChanged[0](
    { device: { newValue: rotated } }, 'local'
  ));
  assertNoRoutableIdentity(
    await loaded.recorded.proxy[0](mainFrame(`https://${ONION_A}/`)),
    'a failed key import must not pair an old HMAC key with a new bearer'
  );
});

test('missingPrivateOrCookieStoreMetadataFailsClosed', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  for (const details of [
    mainFrame(`https://${ONION_A}/`, { incognito: undefined }),
    mainFrame(`https://${ONION_A}/`, { cookieStoreId: undefined }),
    mainFrame(`https://${ONION_A}/`, { cookieStoreId: '' }),
  ]) {
    assertNoRoutableIdentity(
      await onRequest(details),
      'missing browser context metadata must not collapse partitions'
    );
  }
});

test('clearnetRequestsAreDirectAndNeverCarryTheTokenOrPort', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const descriptor = await onRequest(
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

test('webSocketOnionDestinationUsesTheInitiatingSitePartition', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const httpsDescriptor = await onRequest(subresource(
    `https://${ONION_A}/control`,
    'https://alice.co.uk/page',
    { tabId: 14, documentId: 'alice-websocket-document' }
  ));
  const webSocketDescriptor = await onRequest(subresource(
    `wss://${ONION_A}/socket`,
    'https://alice.co.uk/page',
    {
      tabId: 14,
      documentId: 'alice-websocket-document',
      type: 'websocket',
    }
  ));
  assert.strictEqual(webSocketDescriptor.type, 'socks');
  assert.deepStrictEqual(
    plain(webSocketDescriptor),
    plain(httpsDescriptor),
    'destination scheme must not downgrade an onion request or change its ' +
      'initiating-site isolation partition'
  );
});

test('trailingDotFqdnOnionHostStillRoutesAsOnion', async () => {
  const { onRequest } = loadHardenedTokened();
  await drain();
  const descriptor = await onRequest(mainFrame(`https://${ONION_A}./page`));
  assert.strictEqual(
    descriptor.type, 'socks',
    'the FQDN-dot form of an onion host must not evade the FR-001 ' +
      'classification (firstparty.js strips one trailing dot; the router ' +
      'mirrors that normalization)'
  );
  assert.strictEqual(
    descriptor.username, ONION_A_USERNAME,
    'the dot-stripped onion host reaches the same canonical HMAC vector'
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
  const descriptor = await onRequest(details);
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
  await drain();
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
    plain(await noDevice.recorded.proxy[0](mainFrame(`https://${ONION_A}/`))),
    { type: 'direct' },
    'FR-002: without a bearer token the password clause cannot be ' +
      'satisfied — routing to 8881 would violate FR-002, so fail closed'
  );
  // The cache write must agree with the descriptor: fire the
  // cache-writing listener for the tab, then ask via the pinned protocol.
  noDevice.recorded.webRequest[0](mainFrame(`https://${ONION_A}/`));
  await drain();
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
    plain(await emptyToken.recorded.proxy[0](mainFrame(`https://${ONION_A}/`))),
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
  const descriptor = await onRequest(
    subresource(`https://${ONION_A}/x`, 'not a url')
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
  await drain();

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
    plain(await waitForCachedRoute(onMessage, 3, 'tor')), { route: 'tor' },
    'confirmed Tor decision → {route:"tor"} (the iff pin)'
  );
  const unroutedReply = onMessage({ type: GET_ROUTE, tabId: 4 });
  assert.ok(isResponseChannel(unroutedReply), 'owned messages get the channel');
  assert.deepStrictEqual(
    plain(await waitForCachedRoute(onMessage, 4, 'unrouted')),
    { route: 'unrouted' },
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
    (await onRequest(mainFrame(`https://${ONION_A}/`))).password, TOKEN_B,
    'a storage.onChanged event for the device key must refresh the ' +
      'mirrored token — descriptors must never serve a stale credential'
  );

  // Device removal: the mirror drops to absent → fail closed.
  loaded.state.device = null;
  onChanged[0]({ device: { oldValue: { bearerToken: TOKEN_B } } }, 'local');
  await drain();
  assert.deepStrictEqual(
    plain(await onRequest(mainFrame(`https://${ONION_A}/`))), { type: 'direct' },
    'device removal fail-closes the router'
  );

  // Unrelated storage keys must not touch the mirror.
  loaded.state.device = { name: 'd', bearerToken: TOKEN_B, tokenStoredAt: 3 };
  onChanged[0]({ hardening: { newValue: {} } }, 'local');
  await drain();
  assert.deepStrictEqual(
    plain(await onRequest(mainFrame(`https://${ONION_A}/`))), { type: 'direct' },
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


// T150: main-navigation scope must survive mixed requests through either
// callback, and the actual popup must consume that scoped decision.
for (const writer of ['proxy', 'webRequest']) {
  for (const mainTor of [false, true]) {
    test(`mixedTabMainNavigationScope-${writer}-${mainTor ? 'onionMain' : 'directMain'}`, async () => {
      const loaded = loadHardenedTokened();
      await drain();
      const mainURL = mainTor ? `https://${ONION_A}/` : 'https://example.com/';
      const resourceURL = mainTor ? 'https://example.com/image' : `https://${ONION_B}/image`;
      const write = loaded.recorded[writer][0];
      await write(mainFrame(mainURL));
      const expectedRoute = mainTor ? 'tor' : 'unrouted';
      await waitForCachedRoute(loaded.onMessage, 7, expectedRoute);
      await write(subresource(resourceURL, mainURL));
      // Wait until the old implementation's async subresource write has completed.
      // WebCrypto can outlast drain(); observe its opposite value or exhaust bounded turns.
      await waitForCachedRoute(loaded.onMessage, 7, mainTor ? 'unrouted' : 'tor');
      assert.deepStrictEqual(plain(await loaded.onMessage({ type: GET_ROUTE, tabId: 7 })),
        { route: expectedRoute });
      const indicator = {};
      vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../popup/popup.js'), 'utf8'), {
        document: { getElementById: () => indicator },
        browser: {
          tabs: { query: async () => [{ id: 7 }], onUpdated: { addListener() {} } },
          runtime: { sendMessage: loaded.onMessage },
        },
      });
      await drain();
      assert.strictEqual(indicator.textContent,
        `Main navigation decision: ${mainTor ? 'Tor' : 'Direct (unrouted)'}` +
        ' Other requests may use different routes. Connection success is not verified.');
    });
  }

  test(`subresourceAloneCannotClaimMainNavigation-${writer}`, async () => {
    const loaded = loadHardenedTokened();
    await drain();
    await loaded.recorded[writer][0](subresource(`https://${ONION_A}/x`, 'https://example.com/'));
    await waitForCachedRoute(loaded.onMessage, 7, 'tor');
    assert.strictEqual(await loaded.onMessage({ type: GET_ROUTE, tabId: 7 }), undefined);
  });

  for (const replacement of ['navigation', 'close']) {
    test(`lateMainDecisionCannotRestoreStaleTor-${writer}-${replacement}`, async () => {
      let releaseSign;
      const loaded = loadRouter({
        hardeningOk: true,
        crypto: {
          getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
          subtle: {
            importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
            sign(...args) {
              return new Promise((resolve, reject) => {
                releaseSign = () => webcrypto.subtle.sign(...args).then(resolve, reject);
              });
            },
          },
        },
      });
      await drain();
      const write = loaded.recorded[writer][0];
      const onMessage = loaded.recorded.message[0];
      const pending = write(mainFrame(`https://${ONION_A}/`));
      for (let i = 0; i < 100 && !releaseSign; i += 1) await drain(1);
      assert.ok(releaseSign, 'positive control: Tor decision waits for HMAC');
      if (replacement === 'navigation') {
        await write(mainFrame('https://example.com/'));
        await waitForCachedRoute(onMessage, 7, 'unrouted');
      } else {
        loaded.recorded.tabRemoved[0](7);
      }
      await releaseSign();
      await pending;
      await drain();
      assert.deepStrictEqual(plain(await onMessage({ type: GET_ROUTE, tabId: 7 })),
        replacement === 'navigation' ? { route: 'unrouted' } : undefined);
    });
  }
}

for (const writer of ['proxy', 'webRequest']) {
  test(`pendingMainNavigationClearsExistingTor-${writer}`, async () => {
    let holdSign = false;
    let releaseSign;
    const loaded = loadRouter({
      hardeningOk: true,
      crypto: {
        getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
        subtle: {
          importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
          sign(...args) {
            if (!holdSign) return webcrypto.subtle.sign(...args);
            return new Promise((resolve, reject) => {
              releaseSign = () => webcrypto.subtle.sign(...args).then(resolve, reject);
            });
          },
        },
      },
    });
    await drain();
    const write = loaded.recorded[writer][0];
    const onMessage = loaded.recorded.message[0];
    await write(mainFrame(`https://${ONION_A}/`));
    assert.deepStrictEqual(plain(await waitForCachedRoute(onMessage, 7, 'tor')),
      { route: 'tor' }, 'positive control: the prior main decision is Tor');

    holdSign = true;
    const pending = write(mainFrame(`https://${ONION_B}/`));
    for (let i = 0; i < 100 && !releaseSign; i += 1) await drain(1);
    assert.ok(releaseSign, 'positive control: the replacement decision is suspended');
    try {
      assert.strictEqual(await onMessage({ type: GET_ROUTE, tabId: 7 }), undefined,
        'a pending main navigation must not retain the previous Tor decision');
    } finally {
      await releaseSign();
      await pending;
    }
    assert.deepStrictEqual(plain(await waitForCachedRoute(onMessage, 7, 'tor')),
      { route: 'tor' }, 'the replacement publishes its own decision after completion');
  });
}
