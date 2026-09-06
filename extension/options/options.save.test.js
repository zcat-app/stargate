// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// options.save.test.js — Principle-VII unit test for the options page's
// save flow (`options/options.js` + the wiring in `options/options.html`;
// T056). data-model.md §5 puts `^[0-9a-f]{32}$` validation "in the
// options page" — the page is the EDGE where pasted input becomes the
// stored credential, and this suite is its executable spec:
//
//   P1  surface: zero new context globals, exactly one submit listener,
//       no storage I/O at eval time, DOM lookups only the pinned ids
//   P2  fail-closed validation: every invalid input renders the error
//       status and performs ZERO storage touches — a stored malformed
//       token would poison router.js's SOCKS5 password (FR-002); the
//       anchors make a whitespace-padded valid token invalid too
//   P3  a valid save persists via StargateStorage.setDeviceToken
//       (bearerToken + hour-bucket tokenStoredAt; merge preserves a
//       stored name) and renders the saved status
//   P4  a storage failure NEVER reports success: the failure status, a
//       rejected set never the saved status, no unhandled rejection on
//       the page document (storage.test.js A5 swallow-probe lesson)
//   P5  the html wires `../lib/storage.js` + `options.js` as external
//       scripts and provides the pinned element ids (popup.test.js
//       id-drift gate applied to this page) — no inline script, no
//       inline handlers (MV2 CSP: script-src 'self')
//   P6  post-save field hygiene (T118): a RESOLVED save clears the pasted
//       token from #bearer-token — bounding the on-screen lifetime of the
//       secret (Constitution V); a REJECTED write preserves the input for
//       retry — a cleared field beside a failure status would be a lying UI
//
// The warning STRING is not this suite's subject: the landed T034e suite
// (options.test.js) is the canonical-text gate and its html case lifts in
// this same commit. Status-message wording is spec-silent — pinned here
// (T034c precedent: the suite is the machine side of an unpinned
// coupling).
//
// Fidelity/harness (router.test.js + popup.test.js idiom): the sandbox is
// the REAL page scope — lib/storage.js is evaluated into the same context
// before options.js, so saves flow through the real storage wrapper with
// only `browser` and `document` mocked, both access-recording so P1 is
// assertable. options.js ships in THIS commit, so the loader hard-FAILS
// on absence — no tests-first skip state (router.test.js §Fidelity).
// Node built-ins only; no package.json (research.md §10). Token fixtures
// are computed ('ab'.repeat(16)-style, T052 convention) — never a 32-hex
// literal, which the pre-commit secret scanner blocks (T048 commit-gate
// precedent).

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const OPTIONS_PATH = path.join(__dirname, 'options.js');
const OPTIONS_HTML_PATH = path.join(__dirname, 'options.html');
const STORAGE_PATH = path.join(__dirname, '..', 'lib', 'storage.js');

// Matches the data-model.md §5 shape `^[0-9a-f]{32}$` — computed, not a
// literal (gitleaks; see header).
const TOKEN = 'ab'.repeat(16);

// Pinned DOM ids (§Analysis "Pinned surface" / acceptance #2a).
const FORM_ID = 'token-form';
const INPUT_ID = 'bearer-token';
const STATUS_ID = 'status';
const PINNED_IDS = [FORM_ID, INPUT_ID, STATUS_ID];

// Pinned status wording (spec-silent; this suite is its machine side).
const INVALID_MESSAGE = 'Invalid token: expected 32 hexadecimal characters (0-9, a-f).';
const SAVED_MESSAGE = 'Token saved.';
const FAILURE_MESSAGE = 'Could not save the token.';

// ---------------------------------------------------------------------------
// Access-recording mocks. browser exposes ONLY storage.local (get/set over
// an in-memory map with faithful string-key semantics, per-call recording,
// and a live state.failSet switch for P4); every browser namespace touch,
// DOM lookup, listener registration, and element write is recorded. Mock
// elements auto-create per id; the form target records addEventListener so
// the test can fire the real submit handler.
// ---------------------------------------------------------------------------

function makeMocks(state) {
  const recorded = {
    // property paths touched under browser.*, e.g. 'storage.local.get'
    browserTouches: [],
    // { call: 'get'|'set', args } — every storage.local touch
    storageTouches: [],
    // ids passed to document.getElementById
    domLookups: [],
    // { id, type } listener registrations
    listenerAdds: [],
    // { id, prop, value } writes on mock elements
    elementWrites: [],
    // times a fired submit event had preventDefault() called
    preventDefaults: 0,
  };

  const recordedProxy = (prefix, target) => new Proxy(target, {
    get(_t, prop) {
      if (typeof prop === 'string') {
        recorded.browserTouches.push(prefix ? `${prefix}.${prop}` : prop);
      }
      return _t[prop];
    },
  });

  const store = new Map(Object.entries(state.seed || {}));
  const storageLocal = {
    get(keys) {
      recorded.storageTouches.push({ call: 'get', args: [keys] });
      const out = {};
      for (const k of [].concat(keys === null || keys === undefined ? [...store.keys()] : keys)) {
        if (store.has(k)) out[k] = store.get(k);
      }
      return Promise.resolve(out);
    },
    set(items) {
      recorded.storageTouches.push({ call: 'set', args: [items] });
      if (state.failSet) {
        return Promise.reject(new Error('mock: storage set boom'));
      }
      for (const [k, v] of Object.entries(items)) store.set(k, v);
      return Promise.resolve();
    },
  };
  const browser = recordedProxy('', {
    storage: recordedProxy('storage', { local: storageLocal }),
  });

  const elements = new Map();
  const document = {
    getElementById(id) {
      recorded.domLookups.push(id);
      if (!elements.has(id)) {
        // DOM-faithful initial state: textContent is '' on any element,
        // value is '' on any input — never undefined.
        const target = { listeners: {}, textContent: '', value: '' };
        target.addEventListener = (type, fn) => {
          recorded.listenerAdds.push({ id, type });
          (target.listeners[type] = target.listeners[type] || []).push(fn);
        };
        elements.set(id, new Proxy(target, {
          get(_t, prop) {
            return _t[prop];
          },
          set(_t, prop, value) {
            if (typeof prop === 'string') {
              recorded.elementWrites.push({ id, prop, value: String(value) });
            }
            _t[prop] = value;
            return true;
          },
        }));
      }
      return elements.get(id);
    },
  };

  return { browser, document, recorded, store };
}

// ---------------------------------------------------------------------------
// Loader. Evaluates lib/storage.js + options.js into ONE fresh context —
// the real page scope: options.js reaches the token wrapper through the
// real StargateStorage, with only browser/document/console provided.
// Anything else the impl reaches for (fetch, setTimeout, window, self…)
// is a loud ReferenceError — the conformance signal (T034d doctrine).
// ---------------------------------------------------------------------------

function loadOptionsPage(state) {
  const { browser, document, recorded, store } = makeMocks(state);
  const sandbox = { browser, document, console };
  vm.runInNewContext(
    fs.readFileSync(STORAGE_PATH, 'utf8'),
    sandbox,
    { filename: 'lib/storage.js' }
  );
  vm.runInNewContext(
    fs.readFileSync(OPTIONS_PATH, 'utf8'),
    sandbox,
    { filename: 'options/options.js' }
  );
  return { sandbox, document, recorded, store, state };
}

// Conformance gate: hard-fail (never skip) — the impl lands in THIS
// ticket. Pins P1: zero new context globals (T034g doctrine — a page
// script's surface is its wiring, not scope bindings; popup.js precedent).
const PROVIDED_GLOBALS = ['browser', 'console', 'document', 'StargateStorage'];

function requireConformance(sandbox) {
  const extraGlobals = Object.keys(sandbox).filter(
    (name) => !PROVIDED_GLOBALS.includes(name)
  );
  assert.deepStrictEqual(
    extraGlobals.sort(), [],
    'pinned surface violated: options.js must contribute ZERO new context ' +
      'globals — everything inside one IIFE (T034g §doctrine; T034c ' +
      'popup.js precedent); got [' + extraGlobals.join(', ') + ']'
  );
}

// Let already-resolved mock promises and the save chain settle. Bounded
// macrotask turns: deterministic for promise-only chains (T034b).
async function drain(turns = 10) {
  for (let i = 0; i < turns; i += 1) {
    await new Promise(setImmediate);
  }
}

// Fill the field and fire the real submit handler through every registered
// listener (the browser-equivalent of clicking Save or pressing Enter).
// If the implementation leaves a save rejection unhandled, the run fails
// loudly right here — that is the P4 gate, not a harness bug.
async function submit(h, value) {
  h.document.getElementById(INPUT_ID).value = value;
  const form = h.document.getElementById(FORM_ID);
  for (const fn of form.listeners.submit || []) {
    fn({
      preventDefault() {
        h.recorded.preventDefaults += 1;
      },
    });
  }
  await drain();
}

// The rendered status: the current textContent of the pinned status
// element, read back through the mock document.
function renderedStatus(h) {
  return h.document.getElementById(STATUS_ID).textContent;
}

const setTouches = (h) => h.recorded.storageTouches.filter((t) => t.call === 'set');

const hourBucketNow = () => Math.floor(Date.now() / (60 * 60 * 1000));

// ---------------------------------------------------------------------------
// P1 — surface (runs first: conformance gates everything below).
// ---------------------------------------------------------------------------

test('savePageExposesPinnedSurfaceAndDoesNoIoAtEval', () => {
  const h = loadOptionsPage({});
  requireConformance(h.sandbox);
  assert.deepStrictEqual(
    h.recorded.storageTouches, [],
    'options.js must not touch browser.storage at eval time — wiring only; ' +
      'storage work happens inside the submit handler (P1; popup.js ' +
      'render-at-load precedent)'
  );
  assert.deepStrictEqual(
    h.recorded.listenerAdds,
    [{ id: FORM_ID, type: 'submit' }],
    'exactly one submit listener, on the pinned form element — duplicate ' +
      'registrations stack duplicate saves; a click-only or input-only ' +
      'wiring misses the form contract (P1)'
  );
  assert.deepStrictEqual(
    [...new Set(h.recorded.domLookups)].sort(), [...PINNED_IDS].sort(),
    'eval-time DOM lookups target exactly the pinned ids ' +
      '`token-form`/`bearer-token`/`status` (P1; P5 pins the html side)'
  );
  assert.strictEqual(
    renderedStatus(h), '',
    'the status line renders empty before any save attempt — no ' +
      'pre-claimed success (P1)'
  );
});

// ---------------------------------------------------------------------------
// P2 — fail-closed validation: the data-model.md §5 shape at the edge.
// ---------------------------------------------------------------------------

test('invalidTokensRenderErrorAndNeverTouchStorage', async () => {
  // Each entry fails `^[0-9a-f]{32}$` for a different reason: empty,
  // too short, one-short, one-long, uppercase hex, non-hex, and a VALID
  // token with whitespace padding (the anchors must reject it).
  const invalid = [
    '',
    '1234',
    'a'.repeat(31),
    'a'.repeat(33),
    'A'.repeat(32),
    'g'.repeat(32),
    ` ${TOKEN} `,
    undefined,
  ];
  for (const value of invalid) {
    const h = loadOptionsPage({});
    requireConformance(h.sandbox);
    await submit(h, value);
    assert.strictEqual(
      renderedStatus(h), INVALID_MESSAGE,
      `input ${JSON.stringify(value)} must render the error status — ` +
        'data-model.md §5: `^[0-9a-f]{32}$` before save (P2)'
    );
    assert.deepStrictEqual(
      h.recorded.storageTouches, [],
      `input ${JSON.stringify(value)} must perform ZERO storage touches — ` +
        'a malformed token must never reach storage.local, where it would ' +
        'poison router.js\'s SOCKS5 password (P2; FR-002)'
    );
    assert.strictEqual(
      h.recorded.preventDefaults, 1,
      `input ${JSON.stringify(value)}: the submit event is prevented — a ` +
        'default form submission would reload the page and discard the ' +
        'status line (P1)'
    );
  }
});

// ---------------------------------------------------------------------------
// P3 — a valid save: persist through the real wrapper, merge semantics,
// hour-bucket stamp, saved status.
// ---------------------------------------------------------------------------

test('validTokenPersistsThroughSetDeviceTokenAndRendersSaved', async () => {
  const h = loadOptionsPage({ seed: { device: { name: 'alice-laptop' } } });
  requireConformance(h.sandbox);
  const before = hourBucketNow();
  await submit(h, TOKEN);
  const after = hourBucketNow();
  assert.strictEqual(
    renderedStatus(h), SAVED_MESSAGE,
    'a valid token renders the saved status (P3)'
  );
  assert.strictEqual(
    setTouches(h).length, 1,
    'exactly one storage.local.set for one save (P3)'
  );
  // The set argument is allocated inside the vm realm; copy key-by-key
  // into a host object before deepStrictEqual (cross-realm prototype
  // trap — storage.test.js A3).
  assert.deepStrictEqual(
    { ...setTouches(h)[0].args[0].device },
    { name: 'alice-laptop', bearerToken: TOKEN, tokenStoredAt: h.store.get('device').tokenStoredAt },
    'the write goes through StargateStorage.setDeviceToken — merge into ' +
      'the stored device with the token and hour-bucket stamp (P3; ' +
      'data-model.md §5)'
  );
  const device = h.store.get('device');
  assert.strictEqual(
    device.bearerToken, TOKEN,
    'the stored bearerToken equals the pasted input (P3)'
  );
  assert.strictEqual(
    device.name, 'alice-laptop',
    'saving the token MERGES — a stored device name survives (P3; ' +
      'data-model.md §5 shape)'
  );
  assert.ok(
    Number.isInteger(device.tokenStoredAt) &&
      device.tokenStoredAt >= before && device.tokenStoredAt <= after,
    `tokenStoredAt is the current hour-bucket (expected in [${before}, ${after}], ` +
      `got ${device.tokenStoredAt}) — data-model.md §5 stamps the save time (P3)`
  );
});

test('validTokenOnFreshProfileCreatesExactlyTheSchemaShape', async () => {
  // First-run path (US1 first-time setup): no device in storage yet. The
  // page save must still succeed and create exactly the data-model.md §5
  // token fields — never invented siblings.
  const h = loadOptionsPage({});
  requireConformance(h.sandbox);
  await submit(h, TOKEN);
  assert.strictEqual(renderedStatus(h), SAVED_MESSAGE, 'precondition: the save succeeded');
  const device = h.store.get('device');
  assert.deepStrictEqual(
    Object.keys(device).sort(), ['bearerToken', 'tokenStoredAt'],
    'with no stored device, the page save creates exactly the two-field ' +
      'token shape — no invented fields (P3; data-model.md §5)'
  );
  assert.strictEqual(device.bearerToken, TOKEN);
});

// ---------------------------------------------------------------------------
// P4 — storage failure: fail-closed status, no unhandled rejection.
// ---------------------------------------------------------------------------

test('storageFailureRendersFailureStatusNeverSaved', async () => {
  const h = loadOptionsPage({ failSet: true });
  requireConformance(h.sandbox);
  await submit(h, TOKEN);
  assert.strictEqual(
    renderedStatus(h), FAILURE_MESSAGE,
    'a storage failure renders the failure status — reporting success on ' +
      'a failed write would tell the user they are enrolled when the ' +
      'extension is not (P4; Constitution V honesty)'
  );
  assert.strictEqual(
    setTouches(h).length, 1,
    'precondition: the set was attempted exactly once'
  );
  for (const w of h.recorded.elementWrites) {
    assert.notStrictEqual(
      w.value, SAVED_MESSAGE,
      'the saved status is NEVER rendered when the write failed (P4)'
    );
  }
});

// ---------------------------------------------------------------------------
// P6 — post-save field hygiene (T118): bound the on-screen lifetime of the
// pasted secret. Clear ONLY on a resolved write; the failure path keeps the
// input so the user can retry without retyping a 32-char token.
// ---------------------------------------------------------------------------

test('resolvedSaveClearsTheTokenField', async () => {
  const h = loadOptionsPage({});
  requireConformance(h.sandbox);
  await submit(h, TOKEN);
  assert.strictEqual(
    renderedStatus(h), SAVED_MESSAGE,
    'precondition: the save resolved and says so (P6)'
  );
  assert.strictEqual(
    h.document.getElementById(INPUT_ID).value, '',
    'a resolved save clears the pasted token from the field — the §5.1 ' +
      'warning discloses the on-disk exposure, but the still-rendered ' +
      'secret is an avoidable residual with unbounded on-screen lifetime ' +
      '(P6; T118; Constitution V)'
  );
});

test('failedSaveKeepsTheTokenInTheFieldForRetry', async () => {
  const h = loadOptionsPage({ failSet: true });
  requireConformance(h.sandbox);
  await submit(h, TOKEN);
  assert.strictEqual(
    renderedStatus(h), FAILURE_MESSAGE,
    'precondition: the write was rejected and says so (P6)'
  );
  assert.strictEqual(
    h.document.getElementById(INPUT_ID).value, TOKEN,
    'a rejected write must NOT clear the field — the user retries without ' +
      'retyping the token, and a cleared field beside a failure status ' +
      'would be a lying UI (P6; T118)'
  );
});

// ---------------------------------------------------------------------------
// P1 across flows — the whole surface stays inside the pinned contract.
// ---------------------------------------------------------------------------

test('pageSurfaceStaysWithinPinnedDomAndBrowserContract', async () => {
  // One harness through every flow: invalid input, valid save, second
  // save overwriting, and a failed write.
  const h = loadOptionsPage({ seed: { device: { name: 'alice-laptop' } } });
  requireConformance(h.sandbox);
  await submit(h, 'not-a-token');
  await submit(h, TOKEN);
  await submit(h, 'cd'.repeat(16));
  h.state.failSet = true;
  await submit(h, 'ef'.repeat(16));
  await drain();

  const allowedBrowser = new Set([
    'storage',
    'storage.local',
    'storage.local.get',
    'storage.local.set',
  ]);
  for (const touch of h.recorded.browserTouches) {
    assert.ok(
      allowedBrowser.has(touch),
      'options.js touched a browser surface outside the pinned boundary: ' +
        'browser.' + touch + ' (P1 — the page persists one token through ' +
        'storage.local; no tabs/proxy/privacy/notifications access)'
    );
  }
  for (const id of h.recorded.domLookups) {
    assert.ok(
      PINNED_IDS.includes(id),
      'DOM lookups must target only the pinned elements; got "' + id + '" (P1)'
    );
  }
  for (const w of h.recorded.elementWrites) {
    if (w.prop === 'textContent') {
      assert.strictEqual(
        w.id, STATUS_ID,
        'textContent writes must target only the pinned status element (P1)'
      );
    }
    if (w.id === STATUS_ID) {
      assert.strictEqual(
        w.prop, 'textContent',
        'the status line must be written via textContent — the ' +
          'injection-safe write; innerHTML on the status element would be ' +
          'a script-insertion surface (T034c §Analysis precedent)'
      );
    }
  }
  // Non-vacuousness: the flows actually exercised every recorded surface.
  assert.ok(
    h.recorded.storageTouches.some((t) => t.call === 'set') &&
      h.recorded.elementWrites.length >= 3 &&
      h.recorded.preventDefaults === 4,
    'the harness must have exercised a set, status writes, and all four ' +
      'submits for this surface assertion to mean anything'
  );
  assert.strictEqual(
    h.recorded.listenerAdds.length, 1,
    'still exactly one submit listener after every flow — no re-' +
      'registration (P1)'
  );
});

// ---------------------------------------------------------------------------
// P5 — the html side of the wiring contract.
// ---------------------------------------------------------------------------

test('optionsHtmlWiresPinnedScriptsAndIdsWithoutInlineCode', () => {
  const html = fs.readFileSync(OPTIONS_HTML_PATH, 'utf8');
  assert.match(
    html, new RegExp(`<script src="../lib/storage.js"></script>`),
    'options.html must load lib/storage.js before options.js — the save ' +
      'flow reaches the token wrapper through the real StargateStorage ' +
      '(P5; P3 exercises that scope)'
  );
  assert.match(
    html, new RegExp(`<script src="options.js"></script>`),
    'options.html must load options.js (P5)'
  );
  for (const id of PINNED_IDS) {
    assert.match(
      html, new RegExp(`id="${id}"`),
      `options.html must provide the pinned element id="${id}" — ` +
        'options.js wiring targets it; id drift is a CI-caught contract ' +
        'break in either direction (P5; popup.test.js id-drift gate)'
    );
  }
  assert.doesNotMatch(
    html, /<script(?![^>]*\bsrc=)/i,
    'no inline <script> blocks — MV2 CSP is script-src \'self\'; an ' +
      'inline script would be dead code in Firefox (P5)'
  );
  assert.doesNotMatch(
    html, /\son[a-z]+\s*=/i,
    'no inline event handlers (onclick=…) — same CSP contract; the page ' +
      'wires exclusively via options.js addEventListener (P5)'
  );
});
