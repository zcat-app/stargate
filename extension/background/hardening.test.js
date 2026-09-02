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
// surfaces a WebRTC-naming blocking notification plus a
// `storage.local.hardening.lastAuditResult` record. DoH / DoT / HTTP-3
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

function makeBrowser(profile) {
  const recorded = {
    // property paths touched under browser.privacy, e.g. 'privacy.network'
    privacyReads: [],
    // count of any property touches under browser.proxy (must stay 0)
    proxyTouches: [],
    // payloads passed to browser.notifications.create
    notifications: [],
    // argument objects passed to browser.storage.local.set
    storageSets: [],
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
              return Promise.reject(new Error('mock: privacy API unavailable'));
            }
            // Read live through the profile object so a test can flip the
            // simulated profile state between audits (restart semantics).
            return Promise.resolve(profile.peerConnectionEnabled);
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
      return Promise.resolve({});
    },
    set(items) {
      recorded.storageSets.push(items);
      return Promise.resolve();
    },
  };

  const browser = {
    privacy,
    proxy,
    notifications: {
      create(payload) {
        recorded.notifications.push(payload);
        return Promise.resolve(1);
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
    console,
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
  assert.strictEqual(recorded.storageSets.length, 0, 'no failure record on a hardened profile');
});

test('webrtcEnabledFailsClosedAndDialogNamesWebrtc', { skip: !implPresent() && IMPL_ABSENT }, async () => {
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
  assert.ok(recorded.notifications.length >= 1, 'a failing audit surfaces the blocking dialog');
  for (const payload of recorded.notifications) {
    assert.ok(payload && typeof payload.message === 'string', 'dialog payload carries a message string');
    assert.match(payload.message, /webrtc/i, 'dialog names WebRTC as the runtime-blocked surface');
    assert.match(
      payload.message, /peerConnectionEnabled/i,
      'dialog names the remediation (arch §14.5 failure UX item 1)'
    );
    assert.strictEqual(
      payload.requireInteraction, true,
      'dialog is blocking (arch §14.5 failure UX) — a self-dismissing toast is not'
    );
  }
  assert.ok(recorded.storageSets.length >= 1, 'failure is written for the operator');
  const items = recorded.storageSets[recorded.storageSets.length - 1];
  assert.ok(
    items && items.hardening && items.hardening.lastAuditResult !== undefined,
    'failure record lives at storage.local.hardening.lastAuditResult (arch §14.5 Part 2 item 3)'
  );
  const record = JSON.stringify(items.hardening.lastAuditResult);
  assert.match(
    record, /webrtc|peerconnectionenabled/i,
    'failure record identifies the blocked surface'
  );
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
  assert.doesNotMatch(
    dialogText, /\b(doh|dot|trr|http\/3|http3|quic)\b/i,
    'dialog must NOT claim a runtime block on DoH/DoT/HTTP-3 — those are ' +
      'release-cadence-verified (T091; arch §14.5 failure UX item 1); ' +
      'claiming them at runtime is the false assurance T091 removed'
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
});

test('apiReadFailureFailsClosedWithoutThrowing', { skip: !implPresent() && IMPL_ABSENT }, async () => {
  const { sandbox } = loadHardening({ rejectRead: true });
  requireConformance(sandbox);
  // An API misbehaviour (permission, unavailable) must degrade to
  // fail-closed, never to an unhandled rejection on the background page.
  await sandbox.auditHardening();
  assert.strictEqual(sandbox.hardeningOk, FAIL_CLOSED, 'API read failure fails closed');
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
