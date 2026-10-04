// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// hardening.edges.test.js — T055-owned edge cases over the residues the
// frozen T034b suite explicitly named as out of its scope (T034b
// §Analysis §"Residue"): the real-API Settings result shape, the
// never-rejects containment under hostile side effects (including the
// load-time auto-run), and the shared-scope surface exclusivity
// (T034g doctrine). Complements — never replaces — hardening.test.js;
// the two suites share the vm.runInNewContext loader shape (research.md
// §10). Node built-ins only; no package.json.

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const HARDENING_PATH = path.join(__dirname, 'hardening.js');

// Global scope seeded exactly like the T034b loader (plus optional
// per-case overrides), so `Object.keys`-based exclusivity mirrors what
// the browser does to a classic background script: every top-level
// `var` becomes a property of this object.
const SEEDED = ['browser', 'console', 'setTimeout', 'clearTimeout', 'self'];

function loadHardening(options) {
  const {
    setting, // resolved by get(): raw value, {value,...}, or a thrower
    createImpl, // optional (payload) => promise for notifications.create
    setImpl, // optional forbidden-write oracle
    removeImpl, // optional (key) => promise for targeted cleanup
    store = {},
    browserOverride, // replaces the whole browser global when defined
  } = options || {};
  const recorded = { notifications: [], storageSets: [], storageRemoves: [], consoleCalls: [] };

  const browser = browserOverride !== undefined ? browserOverride : {
    privacy: {
      network: {
        peerConnectionEnabled: {
          get() {
            if (typeof setting === 'function') {
              return setting();
            }
            return Promise.resolve(setting);
          },
        },
      },
    },
    notifications: {
      create(payload) {
        recorded.notifications.push(payload);
        return createImpl ? createImpl(payload) : Promise.resolve();
      },
    },
    storage: {
      local: {
        get() {
          return Promise.resolve(store);
        },
        remove(key) {
          recorded.storageRemoves.push(key);
          if (removeImpl) return removeImpl(key);
          delete store[key];
          return Promise.resolve();
        },
        set(items) {
          recorded.storageSets.push(items);
          return setImpl ? setImpl(items) : Promise.resolve();
        },
      },
    },
  };

  const sandbox = { console: Object.fromEntries(['warn', 'error', 'log'].map(level => [level, (...args) => recorded.consoleCalls.push([level, ...args.map(String)])])), setTimeout, clearTimeout };
  if (browserOverride !== undefined) {
    sandbox.browser = browserOverride;
  } else {
    sandbox.browser = browser;
  }
  sandbox.self = sandbox;
  const source = fs.readFileSync(HARDENING_PATH, 'utf8');
  vm.runInNewContext(source, sandbox, { filename: 'background/hardening.js' });
  return { sandbox, recorded };
}

async function drain(turns = 10) {
  for (let i = 0; i < turns; i += 1) {
    await new Promise(setImmediate);
  }
}

test('realApiSettingsShapeResolvesValueAndFlagFollows', async () => {
  // Firefox resolves Settings.get to { value, levelOfControl } — a
  // shape the T034b mock deliberately never produces (it resolves the
  // raw value). The hardened state must be read from `.value`, and the
  // flag must keep following the live profile across audits.
  let profile = { value: false, levelOfControl: 'controllable_by_this_extension' };
  const { sandbox, recorded } = loadHardening({ setting: () => Promise.resolve(profile) });
  await drain();
  assert.strictEqual(
    sandbox.hardeningOk, true,
    'Settings resolving {value: false} is the hardened state'
  );
  assert.strictEqual(recorded.notifications.length, 0, 'silent on hardened');

  profile = { value: true, levelOfControl: 'controllable_by_this_extension' };
  await sandbox.auditHardening();
  assert.strictEqual(
    sandbox.hardeningOk, false,
    'Settings resolving {value: true} must fail closed'
  );
  assert.strictEqual(recorded.notifications.length, 1, 'failure surfaced once');

  profile = { value: false, levelOfControl: 'controllable_by_this_extension' };
  await sandbox.auditHardening();
  assert.strictEqual(sandbox.hardeningOk, true, 'flag follows the read back to hardened');
});

test('T205_sideEffectErrorsNeverEmitRawDetailOrChangeAuthorization', async () => {
  const first = loadHardening({ setting: true, createImpl: () => Promise.reject(new Error('T205_NOTIFICATION_RAW')) });
  await drain();
  await first.sandbox.auditHardening();
  assert.strictEqual(first.sandbox.hardeningOk, false);
  assert.deepStrictEqual(first.recorded.storageSets, []);
  assert.deepStrictEqual(first.recorded.consoleCalls, []);

  const store = { hardening: { lastAuditedAt: 497000, readError: 'T205_LEGACY' }, device: 'preserve' };
  const second = loadHardening({ setting: false, store, removeImpl: () => Promise.reject(new Error('T205_REMOVE_RAW')) });
  await drain();
  await second.sandbox.auditHardening();
  assert.strictEqual(second.sandbox.hardeningOk, false, 'failed cleanup cannot claim initialization success');
  assert.strictEqual(second.sandbox.auditHardening.status, 'unknown');
  assert.ok('hardening' in store, 'failed removal remains observable');
  assert.deepStrictEqual(second.recorded.storageSets, []);
  assert.deepStrictEqual(second.recorded.consoleCalls, []);
  assert.doesNotMatch(JSON.stringify(second.recorded.notifications), /T205_REMOVE_RAW/);
  assert.strictEqual(second.recorded.notifications[0].message,
    'Stargate could not complete its runtime hardening initialization, so all non-Direct routes remain blocked. Restart the browser to retry. WebRTC is the only hardening surface this extension can verify at runtime; this notification does not verify the rest of the browser profile.');
});

test('loadTimeAuditSurvivesHostileBrowserWithoutUnhandledRejection', async () => {
  // A hostile environment must degrade the LOAD-TIME auto-run to
  // fail-closed. Node ≥15 terminates on unhandled rejections, so this
  // case passing at all is the evidence that the floating startup
  // promise is fully contained (T034b §Residue: observability of the
  // load-time path was named as caught by review, not by that suite).
  // No `browser` global at all.
  const absentSandbox = { console, setTimeout, clearTimeout, self: undefined };
  const source = fs.readFileSync(HARDENING_PATH, 'utf8');
  vm.runInNewContext(source, absentSandbox, { filename: 'background/hardening.js' });
  await drain();
  assert.strictEqual(absentSandbox.hardeningOk, false, 'no browser API → fail closed');

  const hollow = loadHardening({ browserOverride: {} });
  await drain();
  assert.strictEqual(hollow.sandbox.hardeningOk, false, 'browser without privacy → fail closed');
});

test('moduleExposesExactlyThePinnedTwoGlobals', async () => {
  // T034g doctrine: firstparty.js / storage.js / hardening.js / router.js
  // load into ONE background-page global scope; the T034b §Analysis pin
  // is "exactly two globals". This suite (T055-owned) enforces it for
  // this module the way firstparty.test.js does for firstPartyDomain.
  const { sandbox } = loadHardening({ setting: false });
  const newGlobals = Object.keys(sandbox).filter((k) => !SEEDED.includes(k)).sort();
  assert.deepStrictEqual(
    newGlobals, ['auditHardening', 'hardeningOk'],
    'hardening.js must expose exactly the pinned surface ' +
      '(auditHardening + hardeningOk) on the shared background scope'
  );
});


test('T205_absentAndMalformedLegacyStateUseOnlyTargetedIdempotentRemoval', async () => {
  for (const value of [undefined, null, 'malformed', ['legacy'], { lastAuditedAt: 497000 }]) {
    const store = { unrelated: 'preserved' };
    if (value !== undefined) store.hardening = value;
    const { sandbox, recorded } = loadHardening({ setting: false, store });
    await drain();
    await sandbox.auditHardening();
    assert.deepStrictEqual(store, { unrelated: 'preserved' });
    assert.deepStrictEqual(recorded.storageRemoves, ['hardening', 'hardening']);
    assert.deepStrictEqual(recorded.storageSets, []);
    assert.strictEqual(sandbox.hardeningOk, true);
  }
});

test('T205_unavailableRemovalFailsClosedWithoutUnhandledStartupRejection', async () => {
  const { sandbox } = loadHardening({ browserOverride: {
    privacy: { network: { peerConnectionEnabled: { get: () => Promise.resolve({ value: false }) } } },
    storage: { local: {} }, notifications: { create: () => Promise.resolve() },
  } });
  await drain();
  assert.strictEqual(sandbox.hardeningOk, false);
  assert.strictEqual(sandbox.auditHardening.status, 'unknown');
});

test('T205_currentFailureClosesGateBeforeNotificationCompletes', async () => {
  let setting = false;
  let release;
  const notification = new Promise(resolve => { release = resolve; });
  const { sandbox } = loadHardening({ setting: () => Promise.resolve({ value: setting }), createImpl: () => notification });
  await drain();
  assert.strictEqual(sandbox.hardeningOk, true);
  setting = true;
  const pending = sandbox.auditHardening();
  await drain();
  assert.strictEqual(sandbox.hardeningOk, false);
  assert.strictEqual(sandbox.auditHardening.status, 'enabled');
  release();
  await pending;
});

test('T205_olderSuccessfulReadCannotOverwriteNewerFailure', async () => {
  let release;
  let calls = 0;
  const held = new Promise(resolve => { release = resolve; });
  const { sandbox } = loadHardening({ setting: () => ++calls === 1 ? held : Promise.resolve({ value: true }) });
  await sandbox.auditHardening();
  assert.strictEqual(sandbox.hardeningOk, false);
  release({ value: false });
  await drain();
  assert.strictEqual(sandbox.hardeningOk, false, 'stale initial success cannot authorize current failure');
  assert.strictEqual(sandbox.auditHardening.status, 'enabled');
});
