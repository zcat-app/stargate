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
    setImpl, // optional (items) => promise for storage.local.set
    browserOverride, // replaces the whole browser global when defined
  } = options || {};
  const recorded = { notifications: [], storageSets: [] };

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
          return Promise.resolve({});
        },
        set(items) {
          recorded.storageSets.push(items);
          return setImpl ? setImpl(items) : Promise.resolve();
        },
      },
    },
  };

  const sandbox = { console, setTimeout, clearTimeout };
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

test('sideEffectRejectionStillResolvesFailClosed', async () => {
  // The audit must never reject even when its own failure side effects
  // misbehave — a rejected notification must not swallow the operator
  // record, and a rejected record write must not swallow the dialog.
  const failingCreate = () => Promise.reject(new Error('mock: notifications unavailable'));
  const first = loadHardening({
    setting: true,
    createImpl: failingCreate,
  });
  await first.sandbox.auditHardening();
  await drain();
  assert.strictEqual(first.sandbox.hardeningOk, false, 'fails closed');
  assert.ok(
    first.recorded.storageSets.length >= 2,
    'the operator record is still written when the dialog rejects ' +
      '(load-time audit + explicit audit)'
  );

  const failingSet = () => Promise.reject(new Error('mock: storage quota'));
  const second = loadHardening({ setting: true, setImpl: failingSet });
  await second.sandbox.auditHardening();
  await drain();
  assert.strictEqual(second.sandbox.hardeningOk, false, 'fails closed');
  assert.ok(
    second.recorded.notifications.length >= 2,
    'the dialog still fires when the record write rejects'
  );
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
