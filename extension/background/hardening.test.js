// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// hardening.test.js — Principle-VII unit test for the extension's runtime
// hardening gate (`background/hardening.js`, FR-004 as amended by T091;
// architecture spec §14.5 Part 2).
//
// Boundary under test (T034b §Analysis — the ONLY runtime surfaces the
// stable Firefox WebExtensions API truthfully exposes): the gate reads
// `browser.privacy.network.peerConnectionEnabled`, fails non-Direct
// routing closed unless the value is exactly `false`, and on failure
// surfaces a WebRTC-naming transient notification and only finite current
// volatile state; no persistent operational record (T205, Constitution III). DoH / DoT / HTTP-3
// are release-cadence-verified out-of-band
// (tests/live-e2e/mullvad-browser-hardening/) and MUST NOT be claimed as
// runtime-gated — a mock that invented those prefs is the false-assurance
// failure mode T091 removed, so this suite asserts their ABSENCE instead.
//
// MV2 background scripts load as browser global scripts, not ES modules,
// so the test loads hardening.js via vm.runInNewContext() with a
// synthesized `browser` global. No UMD wrapper or module shim is added to
// the extension (research.md §10). Node built-ins only — no third-party
// deps, no package.json.

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const HARDENING_PATH = path.join(__dirname, 'hardening.js');

const IMPL_ABSENT =
  'T055 not landed: extension/background/hardening.js does not exist yet ' +
  '(Principle-VII tests-first state; these cases lift and gate T055 when ' +
  'it lands — T068a/T035a precedent)';

const implPresent = () => fs.existsSync(HARDENING_PATH);

// ---------------------------------------------------------------------------
// Access-recording mock. Implements ONLY the surfaces arch §14.5 Part 2
// names for the extension: peerConnectionEnabled, notifications, storage.
// Every browser.privacy namespace access and every browser.proxy access is
// recorded so the no-invented-API-claims property is assertable.
// ---------------------------------------------------------------------------

// Gecko's notifications.create schema (T195). Transcribed from
// toolkit/components/extensions/schemas/notifications.json
// (CreateNotificationOptions) as shipped in Mullvad Browser 153.3.0esr
// (omni.ja chrome/toolkit/content/extensions/schemas/notifications.json).
// Gecko rejects any property outside it, and `buttons` is marked
// `unsupported`. Chromium-only options such as `requireInteraction` are
// therefore absent: a mock that accepted them let this module ship a
// notification the real browser never displayed.
const GECKO_CREATE_NOTIFICATION_PROPERTIES = new Set([
  'type', 'iconUrl', 'appIconMaskUrl', 'title', 'message', 'contextMessage',
  'priority', 'eventTime', 'imageUrl', 'items', 'progress', 'isClickable',
]);
const GECKO_CREATE_NOTIFICATION_REQUIRED = ['type', 'title', 'message'];
const GECKO_NOTIFICATION_TEMPLATES = new Set(['basic', 'image', 'list', 'progress']);

// Returns the rejection message Gecko would produce, or null when valid.
function geckoCreateOptionsRejection(payload) {
  if (payload === null || typeof payload !== 'object') {
    return 'Error processing options: expected an object';
  }
  for (const key of Object.keys(payload)) {
    if (!GECKO_CREATE_NOTIFICATION_PROPERTIES.has(key)) {
      return `Error processing ${key}: Unexpected property "${key}"`;
    }
  }
  for (const key of GECKO_CREATE_NOTIFICATION_REQUIRED) {
    if (payload[key] === undefined) {
      return `Property "${key}" is required`;
    }
  }
  if (!GECKO_NOTIFICATION_TEMPLATES.has(payload.type)) {
    return `Invalid enumeration value "${payload.type}"`;
  }
  if (typeof payload.title !== 'string' || typeof payload.message !== 'string') {
    return 'title and message must be strings';
  }
  return null;
}

function makeBrowser(profile) {
  const recorded = {
    // property paths touched under browser.privacy, e.g. 'privacy.network'
    privacyReads: [],
    // count of any property touches under browser.proxy (must stay 0)
    proxyTouches: [],
    // payloads passed to browser.notifications.create
    notifications: [],
    // payloads Gecko's notifications.create schema would reject
    notificationRejections: [],
    // argument objects passed to browser.storage.local.set
    storageSets: [],
    storageRemoves: [],
    consoleCalls: [],
    store: profile.store || {},
  };

  const privacyNetwork = new Proxy({}, {
    get(_target, prop) {
      if (typeof prop !== 'string') {
        return undefined;
      }
      recorded.privacyReads.push(`privacy.network.${prop}`);
      if (prop === 'peerConnectionEnabled') {
        return {
          get() {
            if (profile.rejectRead) {
              return Promise.reject(new Error(profile.readMarker || 'mock: privacy API unavailable'));
            }
            // Read live through the profile object so a test can flip the
            // simulated profile state between audits (restart semantics).
            return profile.readImpl ? profile.readImpl() : Promise.resolve(profile.peerConnectionEnabled);
          },
        };
      }
      // The real stable API exposes no other privacy.network property.
      return undefined;
    },
  });

  const privacy = new Proxy({}, {
    get(_target, prop) {
      if (typeof prop !== 'string') {
        return undefined;
      }
      recorded.privacyReads.push(`privacy.${prop}`);
      if (prop === 'network') {
        return privacyNetwork;
      }
      return undefined;
    },
  });

  const proxy = new Proxy({}, {
    get(_target, prop) {
      if (typeof prop === 'string') {
        recorded.proxyTouches.push(`proxy.${prop}`);
      }
      return undefined;
    },
  });

  const storageLocal = {
    get(_keys) {
      return Promise.resolve(recorded.store);
    },
    remove(key) {
      recorded.storageRemoves.push(key);
      if (profile.removeError) return Promise.reject(new Error(profile.removeError));
      delete recorded.store[key];
      return Promise.resolve();
    },
    set(items) {
      recorded.storageSets.push(items);
      Object.assign(recorded.store, items);
      return Promise.resolve();
    },
  };

  const browser = {
    privacy,
    proxy,
    notifications: {
      // Behaves like Gecko's `notifications.create`: options outside the
      // CreateNotificationOptions schema reject (T195; Mullvad Browser 153
      // rejects `requireInteraction` with "Unexpected property"), so the
      // notification is never shown. A rejected payload is recorded apart
      // from `notifications`, which holds only what Gecko would display.
      create(payload) {
        const rejection = geckoCreateOptionsRejection(payload);
        if (rejection !== null) {
          recorded.notificationRejections.push(rejection);
          return Promise.reject(new Error(rejection));
        }
        recorded.notifications.push(payload);
        return profile.notificationError ? Promise.reject(new Error(profile.notificationError)) : Promise.resolve(1);
      },
    },
    storage: { local: storageLocal },
  };

  return { browser, recorded };
}

// ---------------------------------------------------------------------------
// Loader. Evaluates hardening.js in a fresh context whose global is the
// sandbox object, so any global the script declares (var / function /
// explicit global assignment / self.x) is readable back off the sandbox —
// that readability is exactly the pinned surface.
// ---------------------------------------------------------------------------

function loadHardening(profile) {
  const { browser, recorded } = makeBrowser(profile);
  const sandbox = {
    browser,
    console: Object.fromEntries(['warn', 'error', 'log'].map(level => [level, (...args) => recorded.consoleCalls.push([level, ...args.map(String)])])),
    setTimeout,
    clearTimeout,
  };
  sandbox.self = sandbox;
  const source = fs.readFileSync(HARDENING_PATH, 'utf8');
  vm.runInNewContext(source, sandbox, { filename: 'background/hardening.js' });
  return { sandbox, recorded };
}

// Conformance gate: hard-fail (not skip) when hardening.js exists but does
// not expose the pinned surface — a silent re-skip here would let T055
// ship ungated (T034b §Analysis "Pinned surface").
function requireConformance(sandbox) {
  assert.ok(
    typeof sandbox.auditHardening === 'function',
    'pinned surface violated: expected a context global function ' +
      '`auditHardening()` (T034b §Analysis; arch §14.5 Part 2). Got: ' +
      typeof sandbox.auditHardening
  );
  assert.ok(
    'hardeningOk' in sandbox,
    'pinned surface violated: expected a context global `hardeningOk` ' +
      'boolean (the flag router.js checks before returning a SOCKS ' +
      'descriptor; a let/const local is not observable — expose it as a ' +
      'global). Got: ' + Object.keys(sandbox).join(', ')
  );
}

// Let already-resolved mock promises and any load-time async chain settle.
// Bounded macrotask turns: deterministic for promise-only chains.
async function drain(turns = 10) {
  for (let i = 0; i < turns; i += 1) {
    await new Promise(setImmediate);
  }
}

const FAIL_CLOSED = false;

test('hardenedProfileAuditsCleanAndSilent', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  const { sandbox, recorded } = loadHardening({ peerConnectionEnabled: false });
  requireConformance(sandbox);
  await sandbox.auditHardening();
  assert.strictEqual(
    sandbox.hardeningOk, true,
    'peerConnectionEnabled === false is the hardened state; routing must not be blocked'
  );
  assert.strictEqual(recorded.notifications.length, 0, 'no failure dialog on a hardened profile');
  assert.strictEqual(recorded.storageSets.length, 0, 'no persistent audit event on a hardened profile');
});

test('webrtcEnabledFailsClosedAndDialogNamesActualPref', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  const { sandbox, recorded } = loadHardening({ peerConnectionEnabled: true });
  requireConformance(sandbox);
  await sandbox.auditHardening();
  await drain();
  assert.strictEqual(
    sandbox.hardeningOk, FAIL_CLOSED,
    'WebRTC enabled must fail non-Direct routing closed (FR-004(b))'
  );
  // A failing profile audits once at load AND once via the explicit call,
  // so the absolute count here is >= 1; the exact per-audit count is
  // pinned by auditRunsAtScriptLoadWithoutExplicitCall (exactly 1 with no
  // explicit call) and reauditObservesChangedProfileState (0 -> 1).
  assert.ok(recorded.notifications.length >= 1, 'a failing audit surfaces the notification');
  for (const payload of recorded.notifications) {
    assert.ok(payload && typeof payload.message === 'string', 'dialog payload carries a message string');
    assert.match(payload.message, /webrtc/i, 'dialog names WebRTC as the runtime-blocked surface');
    assert.match(
      payload.message, /media\.peerconnection\.enabled[^.]*false/i,
      'dialog names the actual about:config remediation (arch §14.5 Part 1)'
    );
    assert.doesNotMatch(
      payload.message, /privacy\.network\.peerConnectionEnabled/,
      'dialog must not present the WebExtensions API path as an about:config preference'
    );
    assert.match(
      payload.message, /about:config/i,
      'dialog identifies where the Firefox preference is configured'
    );
    assert.match(
      payload.message, /restart/i,
      'dialog preserves the browser restart instruction'
    );
    assert.match(
      payload.message, /WebRTC is the only hardening surface this extension can verify at runtime\. DoH, DoT and HTTP\/3 require separate browser-profile checks; this notification does not verify them\./i,
      'dialog states the approved external-check boundary for DoH, DoT and HTTP/3'
    );
    assert.strictEqual(
      payload.requireInteraction, undefined,
      'Gecko rejects requireInteraction, so the notification would never display (T195)'
    );
  }
  assert.deepStrictEqual(
    recorded.notificationRejections, [],
    "every notification option must be accepted by Gecko's notifications.create schema"
  );
  assert.deepStrictEqual(recorded.storageSets, [], 'no persistent failure event (T205)');
});

test('failureDialogNeverClaimsDohDotHttp3RuntimeBlocks', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  const { sandbox, recorded } = loadHardening({ peerConnectionEnabled: true });
  requireConformance(sandbox);
  await sandbox.auditHardening();
  await drain();
  const dialogText = recorded.notifications
    .map((p) => JSON.stringify(p))
    .join(' ');
  const recordText = recorded.storageSets
    .map((items) => JSON.stringify(items && items.hardening ? items.hardening.lastAuditResult : null))
    .join(' ');
  assert.match(
    dialogText, /WebRTC is the only hardening surface this extension can verify at runtime\. DoH, DoT and HTTP\/3 require separate browser-profile checks; this notification does not verify them\./i,
    'dialog states that DoH, DoT and HTTP/3 need external browser-profile checks'
  );
  assert.doesNotMatch(
    recordText, /\b(doh|dot|trr|http\/3|http3|quic)\b/i,
    'failure record must not claim runtime DoH/DoT/HTTP-3 detection either'
  );
  assert.match(dialogText, /webrtc/i, 'the negative constraint must not be satisfied by an empty dialog');
});

test('webrtcPrefUnsetFailsClosed', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  const { sandbox, recorded } = loadHardening({ peerConnectionEnabled: undefined });
  requireConformance(sandbox);
  await sandbox.auditHardening();
  await drain();
  assert.strictEqual(
    sandbox.hardeningOk, FAIL_CLOSED,
    'the pref is reachable but unset: only peerConnectionEnabled === false is hardened'
  );
  assert.ok(recorded.notifications.length >= 1, 'unset-hardening failure is surfaced');
  for (const payload of recorded.notifications) {
    assert.doesNotMatch(
      payload.message, /WebRTC is enabled/i,
      'an unset API value must not be reported as a measured enabled state'
    );
    assert.match(
      payload.message, /could not verify WebRTC is disabled/i,
      'an unset API value is reported as unknown while routing remains fail-closed'
    );
  }
});

test('apiReadFailureFailsClosedWithoutThrowing', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  const { sandbox, recorded } = loadHardening({ rejectRead: true });
  requireConformance(sandbox);
  // An API misbehaviour (permission, unavailable) must degrade to
  // fail-closed, never to an unhandled rejection on the background page.
  await sandbox.auditHardening();
  await drain();
  assert.strictEqual(sandbox.hardeningOk, FAIL_CLOSED, 'API read failure fails closed');
  assert.ok(recorded.notifications.length >= 1, 'unreadable API state is surfaced');
  for (const payload of recorded.notifications) {
    assert.doesNotMatch(
      payload.message, /WebRTC is enabled/i,
      'a failed API read must not be reported as a measured enabled state'
    );
    assert.match(
      payload.message, /could not verify WebRTC is disabled/i,
      'a failed API read is reported as unknown while routing remains fail-closed'
    );
    assert.match(
      payload.message, /media\.peerconnection\.enabled[^.]*false/i,
      'unknown-state remediation still names the actual Firefox preference'
    );
    assert.match(
      payload.message, /restart/i,
      'unknown-state remediation preserves restart guidance'
    );
    assert.match(
      payload.message, /WebRTC is the only hardening surface this extension can verify at runtime\. DoH, DoT and HTTP\/3 require separate browser-profile checks; this notification does not verify them\./i,
      'unknown-state dialog states the approved external-check boundary'
    );
  }
});

test('auditRunsAtScriptLoadWithoutExplicitCall', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  const { sandbox, recorded } = loadHardening({ peerConnectionEnabled: true });
  requireConformance(sandbox);
  await drain();
  assert.strictEqual(
    sandbox.hardeningOk, FAIL_CLOSED,
    'the startup audit ran without an explicit call (arch §14.5 Part 2: read at startup)'
  );
  assert.strictEqual(
    recorded.notifications.length, 1,
    'the load-time audit fires the failure dialog (browser restart = script re-evaluation)'
  );
});

test('reauditObservesChangedProfileState', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  const profile = { peerConnectionEnabled: false };
  const { sandbox, recorded } = loadHardening(profile);
  requireConformance(sandbox);
  await sandbox.auditHardening();
  assert.strictEqual(sandbox.hardeningOk, true);
  assert.strictEqual(recorded.notifications.length, 0);
  profile.peerConnectionEnabled = true; // profile degraded between audits
  await sandbox.auditHardening();
  assert.strictEqual(
    sandbox.hardeningOk, FAIL_CLOSED,
    'a re-audit must re-read the profile, not serve a cached flag'
  );
  assert.strictEqual(recorded.notifications.length, 1, 'the newly-failing audit is surfaced');
});

test('extensionTouchesOnlyRealPrivacyApiSurfaces', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  // T091 must-hold verbatim: "No green test claims a Firefox WebExtension
  // setting that does not exist." The access-recording mock makes any
  // invented pref read (trr.mode, dns.over_tls.*, http3.enable) or proxy
  // surface touch visible.
  const profiles = [
    { peerConnectionEnabled: false },
    { peerConnectionEnabled: true },
    { peerConnectionEnabled: undefined },
    { rejectRead: true },
  ];
  const allowedReads = new Set([
    'privacy.network', // namespace traversal to reach the one real surface
    'privacy.network.peerConnectionEnabled',
  ]);
  for (const profile of profiles) {
    const { sandbox, recorded } = loadHardening(profile);
    requireConformance(sandbox);
    await sandbox.auditHardening();
    await drain();
    for (const read of recorded.privacyReads) {
      assert.ok(
        allowedReads.has(read),
        'hardening.js touched a browser.privacy surface outside the ' +
          'amended boundary: ' + read + ' (T091; arch §14.5 Part 2)'
      );
    }
    assert.deepStrictEqual(
      recorded.proxyTouches, [],
      'the proxy surface belongs to router.js (T054); hardening.js must not touch it'
    );
  }
});

// The mock must actually reject what Gecko rejects, or the schema gate
// above is vacuous (T195).
test('geckoNotificationSchemaMockRejectsRequireInteraction', () => {
  assert.match(
    geckoCreateOptionsRejection({
      type: 'basic', title: 't', message: 'm', requireInteraction: true,
    }),
    /Unexpected property "requireInteraction"/
  );
  assert.strictEqual(
    geckoCreateOptionsRejection({ type: 'basic', title: 't', message: 'm' }), null
  );
});

test('failureNotificationIsDisplayableOnEveryFailureShape', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  for (const profile of [
    { peerConnectionEnabled: true },
    { peerConnectionEnabled: undefined },
    { rejectRead: true },
  ]) {
    const { sandbox, recorded } = loadHardening(profile);
    requireConformance(sandbox);
    await sandbox.auditHardening();
    await drain();
    assert.deepStrictEqual(recorded.notificationRejections, [], JSON.stringify(profile));
    assert.ok(recorded.notifications.length >= 1, JSON.stringify(profile));
  }
});


// T205 acceptance 1–3: the writer/legacy retention are behavioral falsifiers,
// independent of any proposed new status symbol.
test('T205_allAuditShapesNeverWritePersistentEventHourOrRawError', async () => {
  for (const profile of [
    { peerConnectionEnabled: false }, { peerConnectionEnabled: true },
    { peerConnectionEnabled: undefined }, { rejectRead: true, readMarker: 'T205_RAW_READ_497000' },
  ]) {
    const { sandbox, recorded } = loadHardening(profile);
    await drain();
    await sandbox.auditHardening();
    assert.deepStrictEqual(recorded.storageSets, [], 'no event/hour/error record is ever written');
    assert.deepStrictEqual(recorded.consoleCalls, [], 'no diagnostic detail is retained');
    assert.doesNotMatch(JSON.stringify(recorded.notifications), /T205_RAW_READ_497000/);
  }
});

test('T205_successfulStartupDeletesOnlyLegacyKeyAndPreservesClientStateAcrossRestart', async () => {
  const preserved = { device: { bearerToken: 'synthetic-device' }, isolationProfileId: 'synthetic-profile', routes: { default: 'DIRECT' }, unrelated: 'T205_CONFIG' };
  const store = { ...structuredClone(preserved), hardening: { lastAuditedAt: 497000, lastAuditResult: { readError: 'T205_LEGACY_ERROR' } } };
  for (let restart = 0; restart < 2; restart += 1) {
    const { sandbox, recorded } = loadHardening({ peerConnectionEnabled: false, store });
    assert.strictEqual(sandbox.hardeningOk, false, 'restart begins closed, never trusts stored state');
    await drain();
    assert.deepStrictEqual(store, preserved, 'remove obsolete key only');
    assert.deepStrictEqual(recorded.storageRemoves, ['hardening']);
    assert.deepStrictEqual(recorded.storageSets, []);
    assert.strictEqual(sandbox.hardeningOk, true);
  }
});

test('T205_failureThenSuccessClearsCurrentStateWithoutStoredHistory', async () => {
  const profile = { peerConnectionEnabled: true, store: { hardening: { lastAuditedAt: 497000, lastAuditResult: { readError: 'T205_OLD_ERROR' } } } };
  const { sandbox, recorded } = loadHardening(profile);
  await drain();
  assert.strictEqual(sandbox.hardeningOk, false);
  assert.deepStrictEqual(profile.store, {});
  assert.strictEqual(sandbox.auditHardening.status, 'enabled');
  profile.peerConnectionEnabled = false;
  await sandbox.auditHardening();
  assert.strictEqual(sandbox.hardeningOk, true);
  assert.strictEqual(sandbox.auditHardening.status, 'disabled');
  assert.deepStrictEqual(recorded.storageSets, []);
});

test('T205_heldInitialReadCannotAuthorizeFromLegacySuccess', async () => {
  let release;
  const held = new Promise(resolve => { release = resolve; });
  const { sandbox, recorded } = loadHardening({ readImpl: () => held, store: { hardening: { lastAuditResult: { webrtc: 'disabled' } } } });
  await drain();
  assert.strictEqual(sandbox.hardeningOk, false);
  assert.strictEqual(sandbox.auditHardening.status, 'unknown');
  assert.deepStrictEqual(recorded.storageSets, []);
  release({ value: false });
  await drain();
  assert.strictEqual(sandbox.hardeningOk, true);
  assert.strictEqual(sandbox.auditHardening.status, 'disabled');
});
