// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// router.test.js — Principle-VII unit test for the extension's routing
// authority (`background/router.js`; T054). The router is the canonical
// implementation of the `.onion`→127.0.0.1:8881 rule (FR-001) and the
// consumer of the FR-004(b) fail-closed gate, so this suite is its
// executable spec: descriptor contract (FR-001/002/003 + the absent
// failoverTimeout decision), the fail-closed matrix (gate closed / token
// absent / FirstPartyError → blocked, never a guessed username), and the
// background half of the T034c-pinned popup transport (per-tab decision
// cache written by `webRequest.onBeforeRequest`, answered via
// `runtime.onMessage` for `{type:'stargate:getRoute', tabId}` — `{route:
// 'tor'}` iff a confirmed Tor decision is cached; the wrong-positive
// guard: an onion tab canceled while the gate is closed must read
// `blocked`, never `direct` or `tor`).
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
        addListener(fn, filter, extraInfoSpec) {
          recorded.proxy.push(fn);
          recorded.proxyFilters.push(filter);
          recorded.proxyExtraInfo.push(extraInfoSpec);
        },
      },
      settings: {
        get(details) {
          recorded.proxySettingsReads.push(plain(details));
          return state.proxySettings();
        },
      },
    },
    webRequest: {
      onBeforeRequest: {
        addListener(fn, filter, extraInfoSpec) {
          recorded.webRequest.push(fn);
          recorded.webRequestFilters.push(filter);
          recorded.webRequestExtraInfo.push(extraInfoSpec);
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
    // T188: the private-window access check and the blocking notification.
    // Read live off `state` so a test can deny, fail or delay the answer.
    extension: {
      isAllowedIncognitoAccess() {
        recorded.privateAccessChecks.push(1);
        return state.privateAccess();
      },
    },
    notifications: {
      create(...args) {
        recorded.notifications.push(plain(args));
        // Firefox validates NotificationOptions and rejects unknown
        // properties such as Chrome's `requireInteraction` (T188 live).
        const allowed = ['type', 'title', 'message', 'iconUrl', 'contextMessage',
          'priority', 'eventTime', 'imageUrl', 'items', 'progress', 'isClickable'];
        const extra = Object.keys(args[args.length - 1] || {}).filter((k) => !allowed.includes(k));
        if (extra.length > 0) {
          return Promise.reject(new Error(`Unexpected property "${extra[0]}"`));
        }
        return state.notificationsHang
          ? new Promise(() => {})
          : Promise.resolve('stargate-notification');
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

// T188: `browser.proxy.settings.get({})` for a profile running the shipped
// browser-profile/user.js, in the shape Mullvad Browser 153 returned live
// (THREAT-MODEL T188). Read from the template itself, so a template change
// that the router's pinned baseline does not match fails these tests.
function shippedProxySetting() {
  const template = fs.readFileSync(
    path.join(__dirname, '..', '..', 'browser-profile', 'user.js'), 'utf8');
  const pref = (name) => JSON.parse(
    template.match(new RegExp(`^user_pref\\("${name.replace(/\./g, '\\.')}",\\s*(.+)\\);`, 'm'))[1]);
  return {
    levelOfControl: 'controllable_by_this_extension',
    value: {
      proxyType: 'manual',
      autoConfigUrl: '',
      autoLogin: false,
      proxyDNS: pref('network.proxy.socks_remote_dns'),
      httpProxyAll: pref('network.proxy.share_proxy_settings'),
      socksVersion: pref('network.proxy.socks_version'),
      passthrough: pref('network.proxy.no_proxies_on'),
      http: pref('network.proxy.http'),
      ssl: pref('network.proxy.ssl'),
      socks: pref('network.proxy.socks'),
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
    // T188: Firefox grants private-window access; tests deny or fail it.
    privateAccess = () => Promise.resolve(true),
    // T188: the dedicated profile's intact baseline, as Firefox reports it.
    proxySettings = () => Promise.resolve(shippedProxySetting()),
    notificationsHang = false,
  } = options || {};
  const recorded = {
    proxy: [],
    proxyFilters: [],
    proxyExtraInfo: [],
    webRequest: [],
    webRequestFilters: [],
    webRequestExtraInfo: [],
    message: [],
    onChanged: [],
    localGets: [],
    localSets: [],
    committed: [],
    tabRemoved: [],
    publicSuffix: [],
    privateAccessChecks: [],
    notifications: [],
    proxySettingsReads: [],
  };
  const state = {
    device, hardeningOk, isolationProfileId, localSetError, deviceGet,
    privateAccess, proxySettings, notificationsHang,
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
    onRequest: async (details) => primaryProxy(
      await loaded.recorded.proxy[0](details)
    ),
    rawOnRequest: loaded.recorded.proxy[0],
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
  const details = {
    url,
    method: 'GET',
    type: 'main_frame',
    frameId: 0,
    parentFrameId: -1,
    tabId: 7,
    incognito: false,
    cookieStoreId: 'firefox-default',
    documentId: 'top-document-7',
    ...extra,
  };
  if (typeof details.requestId !== 'string') {
    details.requestId = `main:${details.tabId}:${details.documentId}:${details.url}`;
  }
  if (typeof details.proxyInfo === 'undefined') {
    details.proxyInfo = {
      type: 'socks', host: '127.0.0.1', port: 8881, proxyDNS: true,
    };
  }
  return details;
}

function subresource(url, documentUrl, extra) {
  const details = {
    url,
    documentUrl,
    method: 'GET',
    type: 'image',
    frameId: 0,
    parentFrameId: -1,
    tabId: 7,
    incognito: false,
    cookieStoreId: 'firefox-default',
    documentId: 'top-document-7',
    ...extra,
  };
  if (typeof details.requestId !== 'string') {
    details.requestId = `resource:${details.tabId}:${details.documentId}:${details.url}`;
  }
  if (typeof details.proxyInfo === 'undefined') {
    details.proxyInfo = {
      type: 'socks', host: '127.0.0.1', port: 8881, proxyDNS: true,
    };
  }
  return details;
}

function primaryProxy(result) {
  assert.ok(Array.isArray(result), 'protected routing returns a fail-closed proxy chain');
  assert.strictEqual(result.length, 2, 'the chain contains one SOCKS hop and one terminator');
  assert.strictEqual(result[1], null, 'terminal null forbids browser-defined proxy failover');
  return result[0];
}

// T186 / FR-004a: a blocked protected request never gets `null`. Gecko's
// ProxyChannelFilter maps `null` to "no proxy" — an explicit direct
// connection that also bypasses the browser/system proxy — and `x.onion.`
// escapes network.dns.blockDotOnion. The fail-closed result is a SOCKS5h hop
// to a Unix socket path that cannot exist, then the terminal null: nothing
// resolves locally, the connect fails, no failover remains, and the hop
// carries no credential or isolation identity.
const BLOCKED_CHAIN = [{
  type: 'socks',
  host: 'file:///dev/null/stargate-blocked',
  port: 1,
  proxyDNS: true,
}, null];

function assertFailClosed(result, message) {
  assert.notStrictEqual(result, null, message + ' (null would mean Direct)');
  assert.notStrictEqual(result, undefined, message + ' (undefined would mean the default proxy)');
  assert.deepStrictEqual(plain(result), BLOCKED_CHAIN, message + ' (unreachable fail-closed sink)');
  assert.ok(!('username' in result[0]) && !('password' in result[0]),
    message + ' (the sink carries no identity or credential)');
}

function assertNoRoutableIdentity(result, message) {
  assertFailClosed(result, message);
}

// ---------------------------------------------------------------------------
// Descriptor contract (FR-001/002/003 + tasks.md T054 decisions)
// ---------------------------------------------------------------------------

test('onionTopLevelNavigationReturnsCanonicalSocksDescriptor', async () => {
  const { rawOnRequest } = loadHardenedTokened();
  await drain();
  const chain = await rawOnRequest(mainFrame(`https://${ONION_A}/page`));
  assert.deepStrictEqual(
    plain(chain),
    [{
        type: 'socks',
        host: '127.0.0.1',
        port: 8881,
        username: ONION_A_USERNAME,
        password: TOKEN_A,
        proxyDNS: true,
      }, null],
    'FR-001/002/003: the .onion descriptor is socks/127.0.0.1:8881 with ' +
      'the fixed-vector opaque identity as username, the bearer token as password, and ' +
      'proxyDNS true (SOCKS5h), terminated without browser fallback'
  );
  const descriptor = chain[0];
  assert.strictEqual(
    'failoverTimeout' in descriptor, false,
    'tasks.md T054 decision: failoverTimeout is intentionally NOT set — ' +
      'Firefox default applies; the key must be absent, not merely default'
  );
});

test('listenersDeclareFirefoxFiltersAndBlockingCancellation', () => {
  const loaded = loadRouter({ hardeningOk: true });
  assert.deepStrictEqual(plain(loaded.recorded.proxyFilters), [
    { urls: ['<all_urls>'] },
  ]);
  assert.strictEqual(loaded.recorded.proxyExtraInfo[0], undefined);
  assert.deepStrictEqual(plain(loaded.recorded.webRequestFilters), [
    { urls: ['<all_urls>'] },
  ]);
  assert.deepStrictEqual(plain(loaded.recorded.webRequestExtraInfo), [
    ['blocking'],
  ]);
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
    const descriptor = await onRequest(subresource(
      `https://${ONION_A}/same-target.gif`, documentUrl, { documentId }
    ));
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

  const normal = primaryProxy(
    await a.recorded.proxy[0](mainFrame(`https://${ONION_A}/`))
  );
  const device = primaryProxy(await otherDevice.recorded.proxy[0](
    mainFrame(`https://${ONION_A}/`)
  ));
  const profile = primaryProxy(await otherProfile.recorded.proxy[0](
    mainFrame(`https://${ONION_A}/`)
  ));
  const privateMode = primaryProxy(await a.recorded.proxy[0](
    mainFrame(`https://${ONION_A}/`, {
      incognito: true,
      cookieStoreId: 'firefox-private',
    })
  ));
  const container = primaryProxy(await a.recorded.proxy[0](
    mainFrame(`https://${ONION_A}/`, { cookieStoreId: 'firefox-container-1' })
  ));

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
  const [oneChain, twoChain] = await Promise.all([
    onRequest(mainFrame(`https://${ONION_A}/one`)),
    onRequest(mainFrame(`https://${ONION_A}/two`)),
  ]);
  const one = primaryProxy(oneChain);
  const two = primaryProxy(twoChain);
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
    method: 'GET',
    requestId: 'worker-fetch',
    type: 'xmlhttprequest',
    frameId: 4,
    parentFrameId: 0,
    tabId: 9,
    incognito: false,
    cookieStoreId: 'firefox-default',
    documentId: 'frame-alice',
    parentDocumentId: 'top-alice',
    proxyInfo: {
      type: 'socks', host: '127.0.0.1', port: 8881, proxyDNS: true,
    },
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
    primaryProxy(await onRequest(subresource(
      `https://${ONION_A}/current`,
      'https://bob.co.uk/',
      { tabId: 13, documentId: 'new-top' }
    ))).type,
    'socks',
    'the current committed document remains routable'
  );
  loaded.recorded.tabRemoved[0](13);
  assert.strictEqual(
    primaryProxy(await onRequest(subresource(
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
    url: `https://${ONION_A}/nested`, method: 'GET', requestId: 'nested-old',
    type: 'image', frameId: 2,
    parentFrameId: 0, tabId: 12, incognito: false,
    cookieStoreId: 'firefox-default', documentId: 'old-frame',
    parentDocumentId: 'old-top',
    proxyInfo: {
      type: 'socks', host: '127.0.0.1', port: 8881, proxyDNS: true,
    },
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

  for (const [index, original] of cases.entries()) {
    const details = {
      method: 'GET',
      requestId: `untrustworthy-context-${index}`,
      proxyInfo: {
        type: 'socks', host: '127.0.0.1', port: 8881, proxyDNS: true,
      },
      ...original,
    };
    assertNoRoutableIdentity(
      await loaded.rawOnRequest(details),
      'untrustworthy top-level context must not use the onion destination'
    );
    assert.deepStrictEqual(
      plain(await loaded.onBeforeRequest(details)),
      { cancel: true },
      'the final browser dispatch boundary must cancel absent context'
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
    primaryProxy(
      await loaded.recorded.proxy[0](mainFrame(`https://${ONION_A}/`))
    ).type,
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
  const { rawOnRequest } = loadHardenedTokened();
  await drain();
  for (const details of [
    mainFrame(`https://${ONION_A}/`, { incognito: undefined }),
    mainFrame(`https://${ONION_A}/`, { cookieStoreId: undefined }),
    mainFrame(`https://${ONION_A}/`, { cookieStoreId: '' }),
  ]) {
    assertNoRoutableIdentity(
      await rawOnRequest(details),
      'missing browser context metadata must not collapse partitions'
    );
  }
});

test('clearnetRequestsAreDirectAndNeverCarryTheTokenOrPort', async () => {
  const { rawOnRequest } = loadHardenedTokened();
  await drain();
  const descriptor = await rawOnRequest(
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

test('closedHardeningGateCancelsAndRecordsBlocked', async () => {
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
  assertFailClosed(await onRequest(details), 'a closed hardening gate fails closed');
  const webRequestResult = onBeforeRequest(details);
  assert.ok(isResponseChannel(webRequestResult), 'blocking decision uses Firefox async channel');
  assert.deepStrictEqual(plain(await webRequestResult), { cancel: true });
  const blockedReply = onMessage({ type: GET_ROUTE, tabId: 7 });
  assert.ok(
    isResponseChannel(blockedReply),
    'owned messages must be answered via the response channel (a ' +
      'Promise return) — Firefox discards plain synchronous returns ' +
      '(round-1 review Major)'
  );
  assert.deepStrictEqual(
    plain(await blockedReply), { route: 'blocked' },
    'an onion tab canceled behind a closed gate is blocked, never Direct or Tor'
  );
  const indicator = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../popup/popup.js'), 'utf8'), {
    document: { getElementById: () => indicator },
    browser: {
      tabs: { query: async () => [{ id: 7 }], onUpdated: { addListener() {} } },
      runtime: { sendMessage: onMessage },
    },
  });
  await drain();
  assert.strictEqual(
    indicator.textContent,
    'Main navigation decision: Blocked by Stargate' +
      ' Other requests may use different routes. Connection success is not verified.',
    'the popup reports an enforced cancellation as Blocked, not Direct'
  );
});

test('missingOrEmptyTokenFailsClosed', async () => {
  const noDevice = loadRouter({ hardeningOk: true, device: null });
  await drain();
  const missingDetails = mainFrame(`https://${ONION_A}/`);
  assertFailClosed(
    await noDevice.recorded.proxy[0](missingDetails),
    'FR-002: without a bearer token the password clause cannot be ' +
      'satisfied — routing to 8881 would violate FR-002, so fail closed'
  );
  // The cache write must agree with the descriptor: fire the
  // cache-writing listener for the tab, then ask via the pinned protocol.
  assert.deepStrictEqual(
    plain(await noDevice.recorded.webRequest[0](missingDetails)),
    { cancel: true }
  );
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
    { route: 'blocked' },
    'and the tab reads blocked, not Direct or Tor'
  );

  const emptyToken = loadRouter({
    hardeningOk: true,
    device: { name: 'd', bearerToken: '', tokenStoredAt: 1 },
  });
  await drain();
  assertFailClosed(
    await emptyToken.recorded.proxy[0](mainFrame(`https://${ONION_A}/`)),
    'an empty-string token is no token — presence means a non-empty string'
  );

  const malformedToken = loadRouter({
    hardeningOk: true,
    device: { name: 'd', bearerToken: 'not-a-token', tokenStoredAt: 1 },
  });
  await drain();
  assertFailClosed(
    await malformedToken.recorded.proxy[0](mainFrame(`https://${ONION_A}/`)),
    'corrupted storage cannot turn a malformed credential into a route'
  );
  const malformedDetails = mainFrame(`https://${ONION_A}/malformed`);
  assertFailClosed(
    await malformedToken.recorded.proxy[0](malformedDetails),
    'a malformed credential fails closed at the proxy decision'
  );
  assert.deepStrictEqual(
    plain(await malformedToken.recorded.webRequest[0](malformedDetails)),
    { cancel: true },
    'a malformed credential cancels at the final browser dispatch boundary'
  );
});

test('firstPartyErrorFailsClosedWithoutGuessedUsername', async () => {
  const { rawOnRequest } = loadHardenedTokened();
  await drain();
  // Present-but-unparseable governing URL (T034d sentinel contract): the
  // router must surface the failure as a blocked decision — never swallow
  // the sentinel into a guessed, empty, or shared username (the one-
  // routable-string collapse T034d finding 3 forbids).
  const descriptor = await rawOnRequest(
    subresource(`https://${ONION_A}/x`, 'not a url')
  );
  assertFailClosed(descriptor, 'FirstPartyError fails closed without a descriptor identity');
});

test('proxyAndBlockerShareOneDecisionAndRevalidateAppliedRoute', async () => {
  let signs = 0;
  const loaded = loadRouter({
    hardeningOk: true,
    crypto: {
      getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
      subtle: {
        importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
        sign(...args) {
          signs += 1;
          return webcrypto.subtle.sign(...args);
        },
      },
    },
  });
  await drain();
  const details = mainFrame(`https://${ONION_A}/`, { requestId: 'shared-1' });
  primaryProxy(await loaded.recorded.proxy[0](details));
  assert.deepStrictEqual(
    plain(await loaded.recorded.webRequest[0](details)), {},
    'the expected applied SOCKS route is allowed'
  );
  assert.strictEqual(signs, 1, 'both Firefox events consume one HMAC decision');

  const mismatch = mainFrame(`https://${ONION_A}/`, { requestId: 'shared-2' });
  primaryProxy(await loaded.recorded.proxy[0](mismatch));
  mismatch.proxyInfo = { type: 'direct' };
  assert.deepStrictEqual(
    plain(await loaded.recorded.webRequest[0](mismatch)), { cancel: true },
    'an applied Direct/system/unintended route cancels the protected request'
  );
});

test('directAndProtectedMissingRecordHaveDistinctBlockingResults', async () => {
  const loaded = loadHardenedTokened();
  await drain();

  const direct = mainFrame('https://example.com/', { requestId: 'direct-1' });
  assert.deepStrictEqual(plain(await loaded.rawOnRequest(direct)), { type: 'direct' });
  assert.deepStrictEqual(plain(await loaded.onBeforeRequest(direct)), {});

  const missing = mainFrame(`https://${ONION_A}/`, {
    requestId: undefined,
  });
  delete missing.requestId;
  assertFailClosed(
    await loaded.rawOnRequest(missing), 'a protected request without an id fails closed'
  );
  assert.deepStrictEqual(
    plain(await loaded.onBeforeRequest(missing)), { cancel: true },
    'missing cross-event identity is a protected failure, not a recomputation'
  );
});

test('everyBlockedProtectedPathFailsClosedNeverNullOrDefault', async () => {
  // Non-tor decision: the hardening gate is closed.
  const closed = loadRouter({ hardeningOk: false });
  await drain();
  for (const host of [ONION_A, `${ONION_A}.`, `${ONION_A.toUpperCase()}.`, `${ONION_A}..`]) {
    const details = mainFrame(`http://${host}/blocked`, { requestId: `closed:${host}` });
    assertFailClosed(
      await closed.recorded.proxy[0](details),
      `a blocked ${JSON.stringify(host)} request fails closed`
    );
    assert.deepStrictEqual(
      plain(await closed.recorded.webRequest[0](details)), { cancel: true },
      'the cancel listener remains the second layer for ' + JSON.stringify(host)
    );
  }

  // Missing request id, including the trailing-dot form that escapes
  // Gecko's .onion DNS block.
  const loaded = loadHardenedTokened();
  await drain();
  const missing = mainFrame(`http://${ONION_A}./no-id`);
  delete missing.requestId;
  assertFailClosed(await loaded.rawOnRequest(missing), 'a trailing-dot request without an id');

  // Listener failure: a throw inside the proxy listener would make Firefox
  // use its default (system) proxy, so it must also resolve to the sink.
  const hostile = mainFrame(`http://${ONION_A}./listener-failure`, { requestId: 'hostile-1' });
  Object.defineProperty(hostile, 'method', {
    get() { throw new Error('synthetic listener failure'); },
  });
  let result;
  assert.doesNotThrow(() => { result = loaded.rawOnRequest(hostile); },
    'a listener failure must not escape to Firefox\'s default proxy path');
  assertFailClosed(await result, 'a protected listener failure fails closed');

  // Intentional Direct behavior is unchanged, including without an id.
  const clearnet = mainFrame('http://example.com/no-id');
  delete clearnet.requestId;
  assert.deepStrictEqual(plain(await loaded.rawOnRequest(clearnet)), { type: 'direct' });
  const clearnetHostile = mainFrame('http://example.com/listener-failure', { requestId: 'hostile-2' });
  Object.defineProperty(clearnetHostile, 'method', {
    get() { throw new Error('synthetic listener failure'); },
  });
  assert.deepStrictEqual(plain(await loaded.rawOnRequest(clearnetHostile)), { type: 'direct' });
});

test('crossEventFingerprintMismatchCancelsProtectedRequest', async () => {
  const loaded = loadHardenedTokened();
  await drain();
  const proxyDetails = mainFrame(`https://${ONION_A}/original`, {
    requestId: 'fingerprint-mismatch',
  });
  primaryProxy(await loaded.rawOnRequest(proxyDetails));
  const changed = { ...proxyDetails, method: 'POST' };
  assert.deepStrictEqual(
    plain(await loaded.onBeforeRequest(changed)), { cancel: true },
    'requestId reuse with changed route-relevant fields is not the same decision'
  );
});

test('stateChangeBetweenProxyAndBlockingEventsCancels', async () => {
  const loaded = loadRouter({ hardeningOk: true });
  await drain();
  const details = mainFrame(`https://${ONION_A}/`, { requestId: 'rotate-after-proxy' });
  primaryProxy(await loaded.recorded.proxy[0](details));
  loaded.recorded.onChanged[0]({ device: { newValue: {
    name: 'rotated', bearerToken: TOKEN_B, tokenStoredAt: 2,
  } } }, 'local');
  await drain();
  assert.deepStrictEqual(
    plain(await loaded.recorded.webRequest[0](details)), { cancel: true },
    'a proxy decision cannot survive credential-generation change before dispatch'
  );
});

// ---------------------------------------------------------------------------
// T034c protocol: per-tab cache + getRoute responder
// ---------------------------------------------------------------------------

test('getRouteResponderPinnedSemantics', async () => {
  const { rawOnRequest, onBeforeRequest, onMessage } = loadHardenedTokened();
  await drain();

  const tor = mainFrame(`https://${ONION_A}/`, { tabId: 3 });
  await rawOnRequest(tor);
  await onBeforeRequest(tor);
  const direct = mainFrame('https://example.com/', {
      tabId: 4,
      documentUrl: 'https://example.com/',
    });
  await rawOnRequest(direct);
  await onBeforeRequest(direct);
  // Non-tab request (tabId -1: devtools/service-worker/extension traffic)
  // has no indicator to feed and must not poison the cache.
  const noTab = mainFrame(`https://${ONION_B}/`, { tabId: -1 });
  await rawOnRequest(noTab);
  await onBeforeRequest(noTab);

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
    'recorded intentional Direct decision preserves {route:"unrouted"}'
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
    primaryProxy(await onRequest(mainFrame(`https://${ONION_A}/`))).password,
    TOKEN_B,
    'a storage.onChanged event for the device key must refresh the ' +
      'mirrored token — descriptors must never serve a stale credential'
  );

  // Device removal: the mirror drops to absent → fail closed.
  loaded.state.device = null;
  onChanged[0]({ device: { oldValue: { bearerToken: TOKEN_B } } }, 'local');
  await drain();
  assertFailClosed(
    await onRequest(mainFrame(`https://${ONION_A}/`)),
    'device removal fail-closes the router'
  );

  // Unrelated storage keys must not touch the mirror.
  loaded.state.device = { name: 'd', bearerToken: TOKEN_B, tokenStoredAt: 3 };
  onChanged[0]({ hardening: { newValue: {} } }, 'local');
  await drain();
  assertFailClosed(
    await onRequest(mainFrame(`https://${ONION_A}/`)),
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


// T150/T157: the two ordered Firefox events form one routing decision.
async function dispatchRequest(loaded, details) {
  const proxyResult = await loaded.recorded.proxy[0](details);
  const blockingResult = await loaded.recorded.webRequest[0](details);
  return { proxyResult, blockingResult };
}

for (const mainTor of [false, true]) {
  test(`mixedTabMainNavigationScope-${mainTor ? 'onionMain' : 'directMain'}`, async () => {
    const loaded = loadHardenedTokened();
    await drain();
    const mainURL = mainTor ? `https://${ONION_A}/` : 'https://example.com/';
    const resourceURL = mainTor ? 'https://example.com/image' : `https://${ONION_B}/image`;
    await dispatchRequest(loaded, mainFrame(mainURL));
    const expectedRoute = mainTor ? 'tor' : 'unrouted';
    await waitForCachedRoute(loaded.onMessage, 7, expectedRoute);
    await dispatchRequest(loaded, subresource(resourceURL, mainURL));
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

test('subresourceAloneCannotClaimMainNavigation', async () => {
  const loaded = loadHardenedTokened();
  await drain();
  await dispatchRequest(
    loaded, subresource(`https://${ONION_A}/x`, 'https://example.com/')
  );
  assert.strictEqual(await loaded.onMessage({ type: GET_ROUTE, tabId: 7 }), undefined);
});

for (const replacement of ['navigation', 'close']) {
  test(`lateMainDecisionCannotRestoreStaleTor-${replacement}`, async () => {
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
    const details = mainFrame(`https://${ONION_A}/`);
    const pending = loaded.recorded.proxy[0](details);
    for (let i = 0; i < 100 && !releaseSign; i += 1) await drain(1);
    assert.ok(releaseSign, 'positive control: Tor decision waits for HMAC');
    if (replacement === 'navigation') {
      await dispatchRequest(loaded, mainFrame('https://example.com/'));
      await waitForCachedRoute(loaded.recorded.message[0], 7, 'unrouted');
    } else {
      loaded.recorded.tabRemoved[0](7);
    }
    await releaseSign();
    await pending;
    await loaded.recorded.webRequest[0](details);
    assert.deepStrictEqual(
      plain(await loaded.recorded.message[0]({ type: GET_ROUTE, tabId: 7 })),
      replacement === 'navigation' ? { route: 'unrouted' } : undefined
    );
  });
}

test('pendingMainNavigationClearsExistingTor', async () => {
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
  await dispatchRequest(loaded, mainFrame(`https://${ONION_A}/`));
  assert.deepStrictEqual(
    plain(await waitForCachedRoute(loaded.recorded.message[0], 7, 'tor')),
    { route: 'tor' }, 'positive control: the prior main decision is Tor'
  );

  holdSign = true;
  const details = mainFrame(`https://${ONION_B}/`);
  const pending = loaded.recorded.proxy[0](details);
  for (let i = 0; i < 100 && !releaseSign; i += 1) await drain(1);
  assert.ok(releaseSign, 'positive control: the replacement decision is suspended');
  try {
    assert.strictEqual(
      await loaded.recorded.message[0]({ type: GET_ROUTE, tabId: 7 }), undefined,
      'a pending main navigation must not retain the previous Tor decision'
    );
  } finally {
    await releaseSign();
    await pending;
    await loaded.recorded.webRequest[0](details);
  }
  assert.deepStrictEqual(
    plain(await waitForCachedRoute(loaded.recorded.message[0], 7, 'tor')),
    { route: 'tor' }, 'the replacement publishes its own decision after completion'
  );
});

// ---------------------------------------------------------------------------
// T188: private-window access. Mullvad Browser runs every window in private
// browsing. Where the extension runs without private-window access, its
// listeners cannot see private-window requests, so it must say so (blocking
// notification, popup state) and must not route protected requests it can
// see while access is missing, unreadable or not yet confirmed.
// ---------------------------------------------------------------------------

const LABEL_NO_PRIVATE_ACCESS =
  'Stargate is not protecting private windows: "Run in Private Windows" is not ' +
  'allowed or not confirmed. Stargate blocks the .onion requests it can see. ' +
  'Allow it in about:addons > Stargate.';

async function renderPopup(onMessage) {
  const indicator = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../popup/popup.js'), 'utf8'), {
    document: { getElementById: () => indicator },
    browser: {
      tabs: { query: async () => [{ id: 7 }], onUpdated: { addListener() {} } },
      runtime: { sendMessage: onMessage },
    },
  });
  await drain();
  return indicator.textContent;
}

test('missingOrUnreadablePrivateWindowAccessBlocksProtectedRoutingAndNotifies', async () => {
  const cases = [
    ['denied', () => Promise.resolve(false)],
    ['unreadable', () => Promise.reject(new Error('synthetic API failure'))],
    ['throwing', () => { throw new Error('synthetic synchronous failure'); }],
    ['malformed', () => Promise.resolve('true')],
  ];
  for (const [name, privateAccess] of cases) {
    const loaded = loadRouter({ hardeningOk: true, privateAccess });
    await drain();
    requireConformance(loaded.sandbox);
    assert.strictEqual(loaded.recorded.privateAccessChecks.length, 1,
      `${name}: the access check runs once at startup (the about:addons toggle reloads the extension)`);
    for (const host of [ONION_A, `${ONION_A}.`, `${ONION_A.toUpperCase()}.`]) {
      const details = mainFrame(`https://${host}/page`, { requestId: `${name}:${host}` });
      assertFailClosed(await loaded.recorded.proxy[0](details),
        `${name}: a protected ${JSON.stringify(host)} request is not routed without confirmed access`);
      assert.deepStrictEqual(plain(await loaded.recorded.webRequest[0](details)), { cancel: true },
        `${name}: the cancel layer also blocks ${JSON.stringify(host)}`);
    }
    const clearnet = mainFrame('https://example.com/page', { requestId: `${name}:clearnet` });
    assert.deepStrictEqual(plain(await loaded.recorded.proxy[0](clearnet)), { type: 'direct' },
      `${name}: intentional Direct behaviour is unchanged`);

    assert.strictEqual(loaded.recorded.notifications.length, 1,
      `${name}: exactly one blocking notification at startup`);
    const [notification] = loaded.recorded.notifications[0].slice(-1);
    assert.strictEqual(notification.type, 'basic');
    assert.ok(!('requireInteraction' in notification),
      `${name}: only options Firefox accepts, or the notification is never shown`);
    assert.match(notification.title, /private windows/i);
    assert.match(notification.message, /Run in Private Windows/);
    assert.match(notification.message, /about:addons/);
    assert.match(notification.message, /cannot see/,
      `${name}: the notification says the extension cannot see private-window requests`);
    assert.doesNotMatch(notification.message, /protected|safe|routed through Tor/i,
      `${name}: the notification claims no protection it cannot provide`);

    const reply = await loaded.recorded.message[0]({ type: GET_ROUTE, tabId: 7 });
    assert.deepStrictEqual(plain(reply), { route: 'no-private-access' },
      `${name}: the popup's route query reports the unprotected state before any tab decision`);
    assert.strictEqual(await renderPopup(loaded.recorded.message[0]), LABEL_NO_PRIVATE_ACCESS,
      `${name}: the popup shows the unprotected state`);
  }
});

test('protectedDecisionWaitsForThePrivateAccessCheck', async () => {
  let answer;
  const loaded = loadRouter({
    hardeningOk: true,
    privateAccess: () => new Promise((resolve) => { answer = resolve; }),
  });
  await drain();
  const details = mainFrame(`https://${ONION_A}/pending`);
  let settled = false;
  const pending = loaded.recorded.proxy[0](details).then((value) => {
    settled = true;
    return value;
  });
  await drain();
  assert.strictEqual(settled, false,
    'no protected route is decided before private-window access is confirmed');
  const popupReply = loaded.recorded.message[0]({ type: GET_ROUTE, tabId: 7 });
  answer(false);
  assertFailClosed(await pending, 'a denial arriving later still blocks the waiting request');
  assert.deepStrictEqual(plain(await popupReply), { route: 'no-private-access' });

  let grant;
  const granted = loadRouter({
    hardeningOk: true,
    privateAccess: () => new Promise((resolve) => { grant = resolve; }),
  });
  await drain();
  const waiting = granted.recorded.proxy[0](mainFrame(`https://${ONION_A}/granted`));
  await drain();
  grant(true);
  assert.strictEqual(primaryProxy(await waiting).host, '127.0.0.1',
    'a confirmed grant releases the waiting request to the Tor route');
});

test('grantedPrivateWindowAccessRoutesAndStaysSilent', async () => {
  const loaded = loadHardenedTokened();
  await drain();
  const details = mainFrame(`https://${ONION_A}/page`);
  const descriptor = await loaded.onRequest(details);
  assert.strictEqual(descriptor.host, '127.0.0.1');
  assert.deepStrictEqual(plain(await loaded.onBeforeRequest(details)), {});
  assert.deepStrictEqual(plain(await waitForCachedRoute(loaded.onMessage, 7, 'tor')), { route: 'tor' });
  assert.strictEqual(loaded.recorded.privateAccessChecks.length, 1);
  assert.deepStrictEqual(loaded.recorded.notifications, [],
    'no warning is shown when private-window access is granted');
});

// ---------------------------------------------------------------------------
// T188 / option 6: the dedicated profile's fail-closed baseline
// (browser-profile/user.js). Requests the extension does not route with a
// Tor descriptor follow the browser's own proxy settings: extension absent or
// not running (Mullvad's permanent private mode never starts an extension
// lacking private-window access), or its unchanged `{type:'direct'}` result.
// The template sends everything to the T186 Unix SOCKS sink with proxy-side
// DNS, except `<local>` and the ICANN top-level domains. These tests pin the
// shipped template; the live probe proves the browser outcome.
// ---------------------------------------------------------------------------

const PROFILE_TEMPLATE = path.join(__dirname, '..', '..', 'browser-profile', 'user.js');
const PSL_PATH = '/usr/share/publicsuffix/public_suffix_list.dat';
const PSL_SHA256 = '02074b85e6f1454055b82aa7812bcea05f6afd9076e9a60ae1eb30ad61a26881';

function profilePrefs() {
  const prefs = {};
  const pattern = /^user_pref\("([^"]+)",\s*(.+)\);\s*$/gm;
  for (const match of fs.readFileSync(PROFILE_TEMPLATE, 'utf8').matchAll(pattern)) {
    assert.ok(!(match[1] in prefs), `${match[1]} is set once`);
    prefs[match[1]] = JSON.parse(match[2]);
  }
  return prefs;
}

// The template's derivation, as documented in its header: the top-level
// label of every ICANN-section rule, in ASCII form, minus the special-use
// `onion` (the protected route) and `arpa` (special-use reverse-mapping and
// home.arpa names), sorted and de-duplicated.
function deriveTlds(pslText) {
  const icann = pslText.split('// ===BEGIN ICANN DOMAINS===')[1]
    .split('// ===END ICANN DOMAINS===')[0];
  const tlds = new Set();
  for (const raw of icann.split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('//')) continue;
    const label = line.replace(/^!/, '').replace(/^\*\./, '').split('.').pop();
    const ascii = new URL(`http://x.${label}`).hostname.split('.').pop();
    if (ascii !== 'onion' && ascii !== 'arpa') tlds.add(ascii);
  }
  return [...tlds].sort();
}

test('profileTemplateSendsUnroutedRequestsToTheSinkWithProxySideDns', () => {
  const prefs = profilePrefs();
  assert.strictEqual(prefs['network.proxy.type'], 1, 'manual proxy configuration');
  assert.strictEqual(prefs['network.proxy.socks'], BLOCKED_CHAIN[0].host,
    'the default proxy is the T186 Unix sink, whose path cannot exist');
  assert.strictEqual(prefs['network.proxy.socks_version'], 5);
  assert.strictEqual(prefs['network.proxy.socks_remote_dns'], true,
    'names are never resolved locally for proxied requests');
  assert.strictEqual(prefs['network.proxy.socks5_remote_dns'], true);
  for (const name of ['network.proxy.http', 'network.proxy.ssl']) {
    assert.strictEqual(prefs[name], '', `${name} stays empty, so nothing else is proxied`);
  }
  assert.strictEqual(prefs['network.proxy.share_proxy_settings'], false);
});

test('profileTemplateBypassesOnlyIcannTopLevelDomains', () => {
  const entries = profilePrefs()['network.proxy.no_proxies_on'].split(',');
  assert.strictEqual(entries[0], '<local>', 'single-label hosts stay direct');
  const tlds = entries.slice(1);
  for (const entry of tlds) {
    assert.match(entry, /^\.[a-z0-9-]+$/, `${entry} is one leading-dot ASCII top-level label`);
  }
  const labels = tlds.map((entry) => entry.slice(1));
  assert.deepStrictEqual(labels, [...new Set(labels)].sort(), 'sorted and unique');
  for (const kept of ['onion', 'arpa', 'test', 'example', 'invalid', 'local', 'localhost', 'alt', 'i2p']) {
    assert.ok(!labels.includes(kept), `.${kept} is never bypassed: it stays on the sink`);
  }
  for (const icann of ['com', 'org', 'net', 'de', 'uk', 'xn--p1ai']) {
    assert.ok(labels.includes(icann), `.${icann} is an ordinary ICANN domain and goes direct`);
  }
  const header = fs.readFileSync(PROFILE_TEMPLATE, 'utf8');
  assert.ok(header.includes(PSL_SHA256), 'the template records its PSL source hash');
  assert.ok(header.includes('publicsuffix 20231001.0357-0.1'), 'and the package version');
  // Reproduce the list whenever the recorded source file is present. Any
  // other PSL version is a different input: updating is a reviewed promotion.
  if (fs.existsSync(PSL_PATH)) {
    const psl = fs.readFileSync(PSL_PATH);
    const digest = require('node:crypto').createHash('sha256').update(psl).digest('hex');
    if (digest === PSL_SHA256) {
      assert.deepStrictEqual(labels, deriveTlds(psl.toString('utf8')),
        'the shipped list is exactly the documented derivation of the recorded PSL');
    }
  }
});

// ---------------------------------------------------------------------------
// T188 tamper check: while the extension runs, the live proxy settings are
// compared with the shipped baseline. A missing, changed or unreadable
// baseline warns (notification and popup); it never changes routing.
// ---------------------------------------------------------------------------

const BASELINE_WARNING =
  'Warning: the Stargate fail-closed proxy baseline of this profile is missing, ' +
  'changed or unverifiable, so requests Stargate does not route follow the browser ' +
  'proxy settings. Reinstall browser-profile/user.js (quickstart).';

function driftedSetting(change) {
  const setting = shippedProxySetting();
  change(setting.value);
  return setting;
}

test('intactBaselineIsReadAtStartupAndStaysSilent', async () => {
  const loaded = loadHardenedTokened();
  await drain();
  assert.ok(loaded.recorded.proxySettingsReads.length >= 1, 'the baseline is read at startup');
  assert.deepStrictEqual(loaded.recorded.notifications, []);
  const tor = mainFrame(`https://${ONION_A}/page`);
  await loaded.onRequest(tor);
  await loaded.onBeforeRequest(tor);
  assert.deepStrictEqual(plain(await waitForCachedRoute(loaded.onMessage, 7, 'tor')), { route: 'tor' },
    'an intact baseline adds nothing to the route answer');
});

test('changedMissingOrUnreadableBaselineWarnsWithoutChangingRoutes', async () => {
  const cases = [
    ['proxy type none', () => Promise.resolve(driftedSetting((v) => { v.proxyType = 'none'; }))],
    ['socks emptied', () => Promise.resolve(driftedSetting((v) => { v.socks = ''; }))],
    ['socks garbled', () => Promise.resolve(driftedSetting((v) => { v.socks = 'not a proxy host'; }))],
    ['remote DNS off', () => Promise.resolve(driftedSetting((v) => { v.proxyDNS = false; }))],
    ['socks v4', () => Promise.resolve(driftedSetting((v) => { v.socksVersion = 4; }))],
    ['http proxy added', () => Promise.resolve(driftedSetting((v) => { v.http = '127.0.0.1:8080'; }))],
    ['passthrough widened', () => Promise.resolve(driftedSetting((v) => { v.passthrough += ',.onion'; }))],
    ['passthrough narrowed', () => Promise.resolve(driftedSetting((v) => {
      v.passthrough = v.passthrough.replace(',.com,', ',');
    }))],
    ['pac instead', () => Promise.resolve(driftedSetting((v) => {
      v.proxyType = 'autoConfig'; v.autoConfigUrl = 'data:,x';
    }))],
    ['unreadable', () => Promise.reject(new Error('synthetic API failure'))],
    ['malformed', () => Promise.resolve({ value: null })],
  ];
  for (const [name, proxySettings] of cases) {
    const loaded = loadRouter({ hardeningOk: true, proxySettings });
    await drain();
    const warned = loaded.recorded.notifications.filter(
      (args) => /baseline/i.test(JSON.stringify(args)));
    assert.strictEqual(warned.length, 1, `${name}: one baseline notification`);
    const [notification] = warned[0].slice(-1);
    assert.ok(!('requireInteraction' in notification));
    assert.match(notification.message, /browser-profile\/user\.js/);
    assert.match(notification.message, /browser proxy settings/,
      `${name}: says where unrouted requests go instead`);

    const tor = mainFrame(`https://${ONION_A}/page`, { requestId: `${name}:tor` });
    assert.strictEqual(primaryProxy(await loaded.recorded.proxy[0](tor)).host, '127.0.0.1',
      `${name}: the Tor route itself does not depend on the baseline`);
    await loaded.recorded.webRequest[0](tor);
    const reply = plain(await waitForCachedRoute(loaded.recorded.message[0], 7, 'tor'));
    assert.strictEqual(reply.route, 'tor');
    assert.ok(['mismatch', 'unknown'].includes(reply.baseline),
      `${name}: the popup answer carries the baseline state (${JSON.stringify(reply)})`);
    assert.strictEqual(await renderPopup(loaded.recorded.message[0]),
      BASELINE_WARNING + ' Main navigation decision: Tor' +
        ' Other requests may use different routes. Connection success is not verified.',
      `${name}: the popup states the warning before the route`);
  }
});

test('baselineIsComparedWithoutPrivateWindowAccessToo', async () => {
  const loaded = loadRouter({
    hardeningOk: true,
    privateAccess: () => Promise.resolve(false),
    proxySettings: () => Promise.resolve(driftedSetting((v) => { v.socks = ''; })),
  });
  await drain();
  assert.ok(loaded.recorded.proxySettingsReads.length >= 1,
    'reading proxy.settings needs no private-window access, so the check runs');
  assert.strictEqual(loaded.recorded.notifications.length, 2,
    'both the access and the baseline notification are raised');
  assert.deepStrictEqual(plain(await loaded.recorded.message[0]({ type: GET_ROUTE, tabId: 7 })),
    { route: 'no-private-access', baseline: 'mismatch' });
  assert.strictEqual(await renderPopup(loaded.recorded.message[0]),
    BASELINE_WARNING + ' ' + LABEL_NO_PRIVATE_ACCESS);
});

test('baselineIsRecheckedWhenThePopupAsks', async () => {
  let setting = shippedProxySetting();
  const loaded = loadRouter({ hardeningOk: true, proxySettings: () => Promise.resolve(setting) });
  await drain();
  assert.deepStrictEqual(loaded.recorded.notifications, []);
  setting = driftedSetting((v) => { v.socks = ''; });
  const drifted = plain(await loaded.recorded.message[0]({ type: GET_ROUTE, tabId: 7 }));
  assert.deepStrictEqual(drifted, { baseline: 'mismatch' },
    'a change after startup is found at the next popup query');
  assert.strictEqual(loaded.recorded.notifications.length, 1, 'and notified once');
  await loaded.recorded.message[0]({ type: GET_ROUTE, tabId: 7 });
  assert.strictEqual(loaded.recorded.notifications.length, 1, 'without repeating while unchanged');
  setting = shippedProxySetting();
  assert.strictEqual(await loaded.recorded.message[0]({ type: GET_ROUTE, tabId: 7 }), undefined,
    'a restored baseline clears the warning');
});

test('warningsNeverHoldRoutingOrPopupAnswers', async () => {
  const denied = loadRouter({
    hardeningOk: true, privateAccess: () => Promise.resolve(false), notificationsHang: true,
  });
  await drain();
  assertFailClosed(await denied.recorded.proxy[0](mainFrame(`https://${ONION_A}/`)),
    'a notification that never completes cannot delay the blocked decision');
  assert.deepStrictEqual(plain(await denied.recorded.message[0]({ type: GET_ROUTE, tabId: 7 })),
    { route: 'no-private-access' });
  const drifted = loadRouter({
    hardeningOk: true, notificationsHang: true,
    proxySettings: () => Promise.resolve(driftedSetting((v) => { v.socks = ''; })),
  });
  await drain();
  assert.deepStrictEqual(plain(await drifted.recorded.message[0]({ type: GET_ROUTE, tabId: 7 })),
    { baseline: 'mismatch' }, 'nor the popup answer');
});
