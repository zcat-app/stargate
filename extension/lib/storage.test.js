// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// storage.test.js — unit test for the extension's device-schema storage
// wrappers (`lib/storage.js`, T052; data-model.md §5).
//
// Boundary under test: lib/storage.js is a thin async wrapper over
// `browser.storage.local.get/set` carrying exactly the device schema —
// `device.{name, bearerToken, tokenStoredAt}` — for its two consumers:
// router.js (T054) reading the bearer token for the SOCKS5 password and
// options.js (T056) writing the validated one. Deliberately NOT here:
// token-format validation (data-model.md §5 puts `^[0-9a-f]{32}$` "in the
// options page") and every non-device storage.local field (arch §14.4 —
// hardening.js owns its own record). A wrapper that grows policy or shape
// enforcement is the defect this suite exists to catch.
//
// Surface exclusivity (T034g, firstparty.test.js precedent): MV2 lib
// scripts load as classic scripts into ONE background-page global scope,
// so the module may add exactly one global — `StargateStorage` — and no
// other top-level binding; an extra `var`/function declaration is a
// namespace-collision surface. Zero storage touches at load time is also
// pinned: the non-persistent background page must not do I/O at eval.
//
// MV2 classic-script idiom (research.md §10): the module is evaluated via
// vm.runInNewContext() with a synthesized sandbox — a recording
// `browser.storage.local` mock over an in-memory map with faithful
// WebExtensions get() semantics (string / array / defaults-object / null
// forms), plus the host `Date` (epoch, realm-agnostic) and `console`.
// Anything else the impl reaches for is a loud ReferenceError — the
// conformance signal. No third-party deps, no package.json.
//
// Realm note: promises created inside the vm context carry that realm's
// `%Promise.prototype%`, so the async-contract assertion duck-types on
// `.then` — an `instanceof Promise` check would reject a genuinely
// conforming wrapper (same cross-realm trap as firstparty.test.js's
// Error duck-typing).

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const STORAGE_PATH = path.join(__dirname, 'storage.js');

// Matches the data-model.md §5 shape `^[0-9a-f]{32}$` — the format
// options.js (T056) guarantees before calling setDeviceToken.
const HEX32 = 'ab'.repeat(16);

// ---------------------------------------------------------------------------
// Recording `browser.storage.local` mock. get() implements the real
// WebExtensions key forms; set() merges like the real API. Every call is
// recorded so tests can pin call shapes ("exactly one set, argument
// `{ device: d }`") and load-time silence.
// ---------------------------------------------------------------------------

function makeBrowserMock(seed) {
  const store = new Map(Object.entries(seed || {}));
  const touches = [];
  const local = {
    get(keys) {
      touches.push({ call: 'get', args: [keys] });
      if (keys === null || keys === undefined) {
        return Promise.resolve(Object.fromEntries(store));
      }
      if (typeof keys === 'string') {
        const out = {};
        if (store.has(keys)) out[keys] = store.get(keys);
        return Promise.resolve(out);
      }
      if (Array.isArray(keys)) {
        const out = {};
        for (const k of keys) if (store.has(k)) out[k] = store.get(k);
        return Promise.resolve(out);
      }
      // Defaults-object form: absent keys resolve to their defaults.
      const out = {};
      for (const [k, dflt] of Object.entries(keys)) {
        out[k] = store.has(k) ? store.get(k) : dflt;
      }
      return Promise.resolve(out);
    },
    set(items) {
      touches.push({ call: 'set', args: [items] });
      for (const [k, v] of Object.entries(items)) store.set(k, v);
      return Promise.resolve();
    },
  };
  const browser = { storage: { local: local } };
  return { browser, store, touches };
}

function makeSandbox(seed) {
  const { browser, store, touches } = makeBrowserMock(seed);
  return { sandbox: { browser, Date, console }, store, touches };
}

function loadStorage(seed) {
  const { sandbox, store, touches } = makeSandbox(seed);
  const source = fs.readFileSync(STORAGE_PATH, 'utf8');
  vm.runInNewContext(source, sandbox, { filename: 'lib/storage.js' });
  return { sandbox, store, touches };
}

// Conformance gate: hard-fail (never skip) — the impl lands in THIS ticket,
// so a missing/misshapen module is a failure, not a tests-first wait state.
// Pins A6: exactly one new context global (`StargateStorage`) with exactly
// the three wrapper methods (T034g namespace-collision surface).
function requireConformance(sandbox) {
  assert.ok(
    sandbox.StargateStorage && typeof sandbox.StargateStorage === 'object',
    'pinned surface violated: expected a context global object ' +
      '`StargateStorage` (T052 §Acceptance A6; data-model.md §5). Got: ' +
      typeof sandbox.StargateStorage
  );
  assert.deepStrictEqual(
    Object.keys(sandbox.StargateStorage).sort(),
    ['getDevice', 'setDevice', 'setDeviceToken'],
    'pinned surface violated: StargateStorage must expose exactly ' +
      "['getDevice', 'setDevice', 'setDeviceToken'] (T052 §Acceptance A6)"
  );
  for (const method of ['getDevice', 'setDevice', 'setDeviceToken']) {
    assert.strictEqual(
      typeof sandbox.StargateStorage[method], 'function',
      `StargateStorage.${method} must be a function (T052 §Acceptance A6)`
    );
  }
  const extraGlobals = Object.keys(sandbox).filter(
    (name) => name !== 'browser' && name !== 'Date' && name !== 'console'
  );
  assert.deepStrictEqual(
    extraGlobals.sort(),
    ['StargateStorage'],
    'pinned surface violated: expected exactly one new context global, ' +
      "['StargateStorage']; got [" + extraGlobals.join(', ') + '] ' +
      '(T034g §FINDINGS[1]; MV2 classic scripts share one background-page ' +
      'global scope — an extra top-level binding is a namespace-collision ' +
      'surface)'
  );
}

const hourBucketNow = () => Math.floor(Date.now() / (60 * 60 * 1000));

// ---------------------------------------------------------------------------
// A6 — surface (runs first: conformance gates everything below).
// ---------------------------------------------------------------------------

test('moduleExposesExactlyStargateStorage', () => {
  const { sandbox } = loadStorage();
  requireConformance(sandbox);
});

test('moduleDoesNoStorageIoAtLoadTime', () => {
  const { sandbox, touches } = loadStorage();
  requireConformance(sandbox);
  assert.deepStrictEqual(
    touches, [],
    'storage.js must not touch browser.storage at eval time — the ' +
      'non-persistent background page loads four classic scripts and none ' +
      'may do I/O at load (T052 §Analysis P4; arch §14.1 non-persistent)'
  );
});

// ---------------------------------------------------------------------------
// A2 — get fidelity.
// ---------------------------------------------------------------------------

test('getDeviceResolvesStoredValueVerbatim', async () => {
  const { sandbox } = loadStorage();
  requireConformance(sandbox);
  const device = { name: 'alice-laptop', bearerToken: HEX32, tokenStoredAt: 49512 };
  await sandbox.StargateStorage.setDevice(device);
  assert.deepStrictEqual(
    await sandbox.StargateStorage.getDevice(), device,
    'getDevice resolves the stored device value verbatim — all three ' +
      'schema fields survive the round-trip (data-model.md §5; A2)'
  );
});

test('getDeviceResolvesUndefinedWhenKeyAbsent', async () => {
  const { sandbox } = loadStorage();
  requireConformance(sandbox);
  assert.strictEqual(
    await sandbox.StargateStorage.getDevice(), undefined,
    'an absent device key resolves undefined — never a fabricated default ' +
      'device (A2; a default shape here would silently impersonate ' +
      'unconfigured state for router.js/options.js)'
  );
});

// ---------------------------------------------------------------------------
// A3 — set fidelity + call shape.
// ---------------------------------------------------------------------------

test('setDeviceStoresVerbatimUnderDeviceKey', async () => {
  const { sandbox, touches, store } = loadStorage();
  requireConformance(sandbox);
  // A device without token fields is stored as-is: the wrapper does not
  // enforce shape (validation belongs to the options page, data-model §5).
  const device = { name: 'workstation-2' };
  await sandbox.StargateStorage.setDevice(device);
  const setCalls = touches.filter((t) => t.call === 'set');
  assert.strictEqual(setCalls.length, 1, 'setDevice issues exactly one storage.local.set (A3)');
  // The set argument is allocated inside the vm realm, and deepStrictEqual
  // compares prototypes with === — a vm-realm plain object can never
  // deep-equal a host literal directly (same cross-realm trap as the
  // Error/Promise duck-typing notes above). Copy key-by-key into a host
  // object; the structural comparison is then exact.
  assert.deepStrictEqual(
    { ...setCalls[0].args[0] }, { device },
    'the set argument is exactly { device: <value> } — the single ' +
      'data-model.md §5 key, value stored verbatim (A3)'
  );
  assert.deepStrictEqual(
    store.get('device'), { name: 'workstation-2' },
    'the stored value round-trips verbatim (A3)'
  );
});

// ---------------------------------------------------------------------------
// A4 — token stamping: merge, not replace; hour-bucket stamp.
// ---------------------------------------------------------------------------

test('setDeviceTokenStampsHourBucketAndPreservesName', async () => {
  const { sandbox } = loadStorage();
  requireConformance(sandbox);
  await sandbox.StargateStorage.setDevice({ name: 'alice-laptop' });
  const before = hourBucketNow();
  await sandbox.StargateStorage.setDeviceToken(HEX32);
  const after = hourBucketNow();
  const device = await sandbox.StargateStorage.getDevice();
  assert.strictEqual(
    device.bearerToken, HEX32,
    'setDeviceToken persists the token under bearerToken (A4)'
  );
  assert.ok(
    Number.isInteger(device.tokenStoredAt) &&
      device.tokenStoredAt >= before && device.tokenStoredAt <= after,
    `tokenStoredAt is the current hour-bucket (expected in [${before}, ${after}], ` +
      `got ${device.tokenStoredAt}) — data-model.md §5 stamps the save time; ` +
      'the ±0-bucket window only tolerates an hour boundary crossing mid-test (A4)'
  );
  assert.strictEqual(
    device.name, 'alice-laptop',
    'setDeviceToken MERGES into the stored device — an existing name ' +
      'survives; replacing the whole object would erase it (A4)'
  );
});

test('setDeviceTokenCreatesDeviceWhenAbsent', async () => {
  const { sandbox } = loadStorage();
  requireConformance(sandbox);
  const before = hourBucketNow();
  await sandbox.StargateStorage.setDeviceToken(HEX32);
  const device = await sandbox.StargateStorage.getDevice();
  assert.deepStrictEqual(
    Object.keys(device).sort(), ['bearerToken', 'tokenStoredAt'],
    'with no stored device, setDeviceToken creates exactly the two-field ' +
      'device object — no invented fields (A4; data-model.md §5)'
  );
  assert.strictEqual(device.bearerToken, HEX32);
  assert.ok(
    device.tokenStoredAt >= before && device.tokenStoredAt <= hourBucketNow(),
    'the created device carries the current hour-bucket stamp (A4)'
  );
});

// ---------------------------------------------------------------------------
// A5 — async contract: thenables in, rejections propagated.
// ---------------------------------------------------------------------------

test('wrappersReturnThenablesAndRejectPropagates', async () => {
  const { sandbox } = loadStorage();
  requireConformance(sandbox);
  for (const [method, args] of [
    ['getDevice', []],
    ['setDevice', [{ name: 'x' }]],
    ['setDeviceToken', [HEX32]],
  ]) {
    const result = sandbox.StargateStorage[method](...args);
    assert.strictEqual(
      typeof result?.then, 'function',
      `${method} must return a thenable — router.js awaits it inside ` +
        'proxy.onRequest; a synchronous return/throw would break T054 (A5)'
    );
    await result;
  }
  // Rejection propagation: a storage failure surfaces to the caller — the
  // wrapper must not swallow it into a resolved undefined (A5). Probed for
  // ALL THREE wrappers: the round-1 review demonstrated a swallow mutant
  // of setDevice's `await browser.storage.local.set` surviving a get-only
  // probe 8/8 — a real storage failure during T056's save would have
  // resolved as success for the caller.
  const swallowProbe = async (method, args, api, message) => {
    const { sandbox } = loadStorage();
    requireConformance(sandbox);
    sandbox.browser.storage.local[api] = () => Promise.reject(new Error(message));
    await assert.rejects(
      sandbox.StargateStorage[method](...args),
      new RegExp(message),
      `a storage.local failure propagates out of ${method} (A5)`
    );
  };
  await swallowProbe('getDevice', [], 'get', 'storage get boom');
  await swallowProbe('setDevice', [{ name: 'x' }], 'set', 'storage set boom');
  // setDeviceToken's set path rejects through the merge: getDevice runs
  // against the real mock first, the stamped set() is what fails.
  await swallowProbe('setDeviceToken', [HEX32], 'set', 'storage set boom');
});
