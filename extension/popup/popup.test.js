// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// Tests the main-navigation decision display contract in spec.md §Per-tab
// indicator scope (T150). The background is the routing authority; the popup
// only queries the active tab and writes textContent. Node VM mocks exercise
// message failures and ordering, not real browser transport or tunnel success.

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const POPUP_PATH = path.join(__dirname, 'popup.js');
const POPUP_HTML_PATH = path.join(__dirname, 'popup.html');

const IMPL_ABSENT =
  'T057 not landed: extension/popup/popup.js does not exist yet ' +
  '(Principle-VII tests-first state; these cases lift and gate T057 ' +
  'when it lands — T068a/T034b/T034e precedent)';

const HTML_ABSENT =
  'T057 not landed: extension/popup/popup.html does not exist yet ' +
  '(same tests-first state; this case gates the popup.html side of the ' +
  'pinned DOM contract — T034c §Residue promotion)';

const implPresent = () => fs.existsSync(POPUP_PATH);
const htmlPresent = () => fs.existsSync(POPUP_HTML_PATH);

// Canonical labels from spec.md §Per-tab indicator scope (T150).
const SCOPE = ' Other requests may use different routes. Connection success is not verified.';
const LABEL_TOR = 'Main navigation decision: Tor' + SCOPE;
const LABEL_DIRECT = 'Main navigation decision: Direct (unrouted)' + SCOPE;
const LABEL_UNKNOWN = 'Main navigation decision: Unknown' + SCOPE;

// Pinned protocol (T034c §Analysis finding 1).
const GET_ROUTE = 'stargate:getRoute';

// 56 base32 chars (a-z, 2-7) + `.onion` — syntactically plausible v3
// address (T034d fixture style; checksum validity is irrelevant here).
const ONION = 'abcd2345'.repeat(7) + '.onion';

// ---------------------------------------------------------------------------
// Access-recording mocks. Implements ONLY the pinned surface: tabs.query,
// tabs.onUpdated.addListener, runtime.sendMessage, and a minimal document
// with getElementById. Every browser namespace touch, DOM lookup and
// element write is recorded so the display-only property is assertable.
// The active tab and the reply function live on a mutable `state` object
// read live at call time, so a test can flip the simulated cache between
// renders (case (c)).
// ---------------------------------------------------------------------------

function makeMocks(state) {
  const recorded = {
    // property paths touched under browser.*, e.g. 'tabs.query'
    browserTouches: [],
    // option objects passed to tabs.query
    tabsQueries: [],
    // listeners registered on tabs.onUpdated
    onUpdatedListeners: [],
    // payloads passed to runtime.sendMessage
    messages: [],
    // ids passed to document.getElementById
    domLookups: [],
    // { id, prop, value } writes on mock elements
    elementWrites: [],
  };

  const recordedProxy = (prefix, target) => new Proxy(target, {
    get(_t, prop) {
      if (typeof prop === 'string') {
        recorded.browserTouches.push(prefix ? `${prefix}.${prop}` : prop);
      }
      return _t[prop];
    },
  });

  const onUpdated = recordedProxy('tabs.onUpdated', {
    addListener(fn) {
      recorded.onUpdatedListeners.push(fn);
    },
  });

  const tabs = recordedProxy('tabs', {
    query(options) {
      recorded.tabsQueries.push(options);
      return Promise.resolve([state.activeTab]);
    },
    onUpdated,
  });

  const runtime = recordedProxy('runtime', {
    sendMessage(payload) {
      recorded.messages.push({ payload });
      // A rejected promise here is the "background page gone" case; if
      // the implementation leaves it unhandled, the run fails loudly.
      return state.reply(payload);
    },
  });

  const browser = recordedProxy('', { tabs, runtime });

  const elements = new Map();
  const document = {
    getElementById(id) {
      recorded.domLookups.push(id);
      if (!elements.has(id)) {
        elements.set(id, new Proxy({}, {
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

  return { browser, document, recorded };
}

// ---------------------------------------------------------------------------
// Loader. Evaluates popup.js in a fresh context whose globals are exactly
// the pinned set — `browser`, `document`, `console`. Nothing else: any
// further global the implementation reaches for (URL, setTimeout, fetch,
// storage, self…) is a loud ReferenceError, which is the conformance
// signal (T034d doctrine).
// ---------------------------------------------------------------------------

function loadPopup(state) {
  const { browser, document, recorded } = makeMocks(state);
  const sandbox = { browser, document, console };
  const source = fs.readFileSync(POPUP_PATH, 'utf8');
  vm.runInNewContext(source, sandbox, { filename: 'popup/popup.js' });
  return { sandbox, recorded, state };
}

// Conformance gate: hard-fail (not skip) when popup.js exists but does
// not respect the pinned surface — a silent re-skip here would let T057
// ship ungated (T034c §Analysis "Pinned surface"; T034d/T034g doctrine).
const PROVIDED_GLOBALS = ['browser', 'console', 'document'];

function requireConformance(sandbox) {
  const extraGlobals = Object.keys(sandbox).filter(
    (name) => !PROVIDED_GLOBALS.includes(name)
  );
  assert.deepStrictEqual(
    extraGlobals.sort(), [],
    'pinned surface violated: popup.js must be self-contained — zero new ' +
      'context globals (T034c §Analysis "Pinned surface"); got [' +
      extraGlobals.join(', ') + ']'
  );
}

// Let already-resolved mock promises and any load-time async chain settle.
// Bounded macrotask turns: deterministic for promise-only chains (T034b).
async function drain(turns = 10) {
  for (let i = 0; i < turns; i += 1) {
    await new Promise(setImmediate);
  }
}

// Simulate one tabs.onUpdated event through every registered listener
// (case (c)'s prescribed simulation), then let the re-render settle.
async function fireOnUpdated(h, tabId, changeInfo, tab) {
  for (const listener of h.recorded.onUpdatedListeners) {
    listener(tabId, changeInfo, tab);
  }
  await drain();
}

// The rendered label: the current textContent of the pinned indicator
// element, read back through the mock document.
function renderedLabel(h) {
  return h.sandbox.document.getElementById('route-indicator').textContent;
}

// Pinned message-shape assertion, field-wise. deepStrictEqual walks
// prototypes, and a payload created inside the vm realm carries the vm
// realm's Object.prototype — a host-side deepStrictEqual against
// `{ type, tabId }` fails on the realm mismatch, not on content (the
// same cross-realm trap T034d hit with the realm-local Error
// constructor; first falsification round found exactly this). Compare
// fields strictly and pin the key set instead — that pins the wire
// shape, extra fields included.
function assertGetRouteMessage(payload, tabId, what) {
  assert.ok(
    !!payload && typeof payload === 'object',
    what + ': the getRoute message must be the pinned object shape'
  );
  assert.deepStrictEqual(
    Object.keys(payload).sort(), ['tabId', 'type'],
    what + ': the getRoute message carries exactly {type, tabId} — an ' +
      'extra field is protocol drift (T034c §Analysis finding 1)'
  );
  assert.strictEqual(
    payload.type, GET_ROUTE,
    what + ': the getRoute message type is the pinned "' + GET_ROUTE + '"'
  );
  assert.strictEqual(
    payload.tabId, tabId,
    what + ': the getRoute message names the active tab\'s id'
  );
}

const skip = () => (!implPresent() ? IMPL_ABSENT : false);

test('onionActiveTabShowsExactTorLabel', { skip: skip() }, async () => {
  const state = {
    activeTab: { id: 7, url: `https://${ONION}/page` },
    reply: () => Promise.resolve({ route: 'tor' }),
  };
  const h = loadPopup(state);
  requireConformance(h.sandbox);
  await drain();
  assert.strictEqual(
    renderedLabel(h), LABEL_TOR,
    'body case (a): an active tab the router routed to Tor shows the ' +
      'canonical label byte-exact (tasks.md T057; spec US1 scenario 1)'
  );
  assert.strictEqual(
    h.recorded.messages.length, 1,
    'exactly one getRoute ask for the initial render'
  );
  assertGetRouteMessage(
    h.recorded.messages[0].payload, 7,
    'the popup asks the background for the active tab\'s routing decision ' +
      '— it never decides from the tab URL (T034c §Analysis findings 1–2; ' +
      'T057 "reading the routing decision from ' +
      'webRequest.onBeforeRequest cache")'
  );
  const q = h.recorded.tabsQueries[0];
  assert.ok(
    q && q.active === true && q.currentWindow === true,
    'tabs.query must select the active tab of the current window — the ' +
      'per-tab binding (T034c §Analysis "Pinned surface"); got ' +
      JSON.stringify(q)
  );
});

test('clearnetActiveTabShowsExactUnroutedLabel', { skip: skip() }, async () => {
  const state = {
    activeTab: { id: 7, url: 'https://example.com/page' },
    reply: () => Promise.resolve({ route: 'unrouted' }),
  };
  const h = loadPopup(state);
  requireConformance(h.sandbox);
  await drain();
  assert.strictEqual(
    renderedLabel(h), LABEL_DIRECT,
    'body case (b): a clearnet active tab shows the canonical unrouted ' +
      'label byte-exact (tasks.md T057)'
  );
});

test('sameTabOnionToClearnetNavigationClearsStaleTorLabel', { skip: skip() }, async () => {
  const state = {
    activeTab: { id: 7, url: `https://${ONION}/page` },
    reply: () => Promise.resolve({ route: 'tor' }),
  };
  const h = loadPopup(state);
  requireConformance(h.sandbox);
  await drain();
  assert.strictEqual(
    renderedLabel(h), LABEL_TOR,
    'precondition: the routed onion tab shows Tor'
  );
  // The same tab navigates clearnet; the cache entry goes with it (the
  // router records no Tor decision for the new host), so the background
  // has nothing to confirm for tab 7 any more.
  state.activeTab = { id: 7, url: 'https://example.com/other' };
  state.reply = () => Promise.resolve(undefined);
  await fireOnUpdated(h, 7, { url: 'https://example.com/other' }, state.activeTab);
  assert.strictEqual(
    renderedLabel(h), LABEL_UNKNOWN,
    'body case (c): after an in-tab navigation the label updates with no ' +
      'stale `Route: Tor` carry-over from the previous navigation'
  );
  assert.strictEqual(
    h.recorded.messages.length, 2,
    'the update re-asks the live cache — the popup must never render from ' +
      'remembered state (T034c §Analysis "Live re-ask")'
  );
  assertGetRouteMessage(
    h.recorded.messages[1].payload, 7,
    'the re-ask is the same pinned shape, for the same tab'
  );
});

test('sameTabClearnetToOnionNavigationShowsTorOnFreshCacheAnswer', { skip: skip() }, async () => {
  const state = {
    activeTab: { id: 7, url: 'https://example.com/' },
    reply: () => Promise.resolve(undefined),
  };
  const h = loadPopup(state);
  requireConformance(h.sandbox);
  await drain();
  assert.strictEqual(
    renderedLabel(h), LABEL_UNKNOWN,
    'precondition: the unrouted tab shows the safe default'
  );
  // The mirror of case (c): navigation arrives on the same tab and the
  // cache now holds a Tor decision for it. An implementation that
  // "passes" case (c) by blindly flipping to Direct on any event fails
  // here — this is that falsifier (T034c §Acceptance 4).
  state.activeTab = { id: 7, url: `https://${ONION}/` };
  state.reply = () => Promise.resolve({ route: 'tor' });
  await fireOnUpdated(h, 7, { url: `https://${ONION}/` }, state.activeTab);
  assert.strictEqual(
    renderedLabel(h), LABEL_TOR,
    'clearnet→onion navigation on the active tab shows Tor from the ' +
      'fresh cache answer, not from URL parsing (T034c §Analysis finding 2)'
  );
  assert.strictEqual(
    h.recorded.messages.length, 2,
    'the arrival render also comes from a fresh ask'
  );
});

test('coldStartEmptyCacheShowsUnknownLabel', { skip: skip() }, async () => {
  const state = {
    activeTab: { id: 7, url: 'https://example.com/' },
    // Cold start: the onBeforeRequest cache holds nothing for this tab,
    // so the background has no confirmed decision to reply with.
    reply: () => Promise.resolve(undefined),
  };
  const h = loadPopup(state);
  requireConformance(h.sandbox);
  await drain();
  assert.strictEqual(
    renderedLabel(h), LABEL_UNKNOWN,
    'body case (d): the popup MUST NOT display "Tor" without a confirmed ' +
      'routing decision for the current tab — a wrong-positive would tell ' +
      'the user they are routed when they are not'
  );
});

test('nonTorRepliesNeverRenderTorLabel', { skip: skip() }, async () => {
  // The fail-closed display matrix: `Route: Tor` requires exactly
  // route === 'tor'; every absent or unrecognizable answer degrades to
  // the safe default (T034c §Analysis must-hold 1). 'TOR' pins that the
  // comparison is exact, not case-folded.
  const replies = [
    undefined, null, {}, { route: 'unrouted' }, { route: 'direct' }, { route: 'TOR' },
  ];
  for (const reply of replies) {
    const state = {
      activeTab: { id: 7, url: `https://${ONION}/page` },
      reply: () => Promise.resolve(reply),
    };
    const h = loadPopup(state);
    requireConformance(h.sandbox);
    await drain();
    assert.strictEqual(
      renderedLabel(h), reply && reply.route === 'unrouted' ? LABEL_DIRECT : LABEL_UNKNOWN,
      `reply ${JSON.stringify(reply)} on an onion tab must render the safe ` +
        'default — `Route: Tor` requires exactly route === \'tor\' ' +
        '(T034c §Analysis fail-closed display mapping)'
    );
  }
});

test('sendMessageFailureRendersUnknownWithoutThrowing', { skip: skip() }, async () => {
  const state = {
    activeTab: { id: 7, url: `https://${ONION}/page` },
    // Background page gone/reloading: the ask rejects. If the
    // implementation leaves the rejection unhandled, the run fails
    // loudly right here — that is the gate, not a harness bug.
    reply: () => Promise.reject(new Error('mock: background page gone')),
  };
  const h = loadPopup(state);
  requireConformance(h.sandbox);
  await drain();
  assert.strictEqual(
    renderedLabel(h), LABEL_UNKNOWN,
    'a failed ask degrades to the safe default — never an unhandled ' +
      'rejection on the popup document, never "Tor" (T034b ' +
      'apiReadFailureFailsClosedWithoutThrowing precedent)'
  );
});

test('backgroundTabUpdateNeverRerendersActiveIndicator', { skip: skip() }, async () => {
  const state = {
    activeTab: { id: 7, url: 'https://example.com/' },
    // The cache holds a Tor decision — but for tab 9, not the active tab.
    reply: (payload) => (payload && payload.tabId === 9
      ? Promise.resolve({ route: 'tor' })
      : Promise.resolve(undefined)),
  };
  const h = loadPopup(state);
  requireConformance(h.sandbox);
  await drain();
  assert.strictEqual(
    renderedLabel(h), LABEL_UNKNOWN,
    'precondition: the active clearnet tab shows the safe default'
  );
  // A background tab navigates to an onion site while the popup is open
  // on the clearnet active tab.
  await fireOnUpdated(h, 9, { url: `https://${ONION}/` }, { id: 9, url: `https://${ONION}/` });
  assert.strictEqual(
    renderedLabel(h), LABEL_UNKNOWN,
    'another tab navigating to .onion must not move the active tab\'s ' +
      'indicator — cross-tab bleed is the case-(d) wrong-positive reached ' +
      'sideways (T034c §Analysis per-tab binding). The contract is the ' +
      'rendered label, not the ask strategy: an implementation may filter ' +
      'events by tabId or re-ask and render the active tab\'s own answer — ' +
      'both keep this label at the safe default.'
  );
});

test('popupTouchesOnlyPinnedBrowserSurfaces', { skip: skip() }, async () => {
  // One harness through every flow: routed load, active-tab navigation,
  // a foreign-tab update, and a failed ask.
  const state = {
    activeTab: { id: 7, url: `https://${ONION}/page` },
    reply: () => Promise.resolve({ route: 'tor' }),
  };
  const h = loadPopup(state);
  requireConformance(h.sandbox);
  await drain();
  state.activeTab = { id: 7, url: 'https://example.com/other' };
  state.reply = () => Promise.resolve(undefined);
  await fireOnUpdated(h, 7, { url: 'https://example.com/other' }, state.activeTab);
  await fireOnUpdated(h, 9, { url: `https://${ONION}/` }, { id: 9, url: `https://${ONION}/` });
  state.reply = () => Promise.reject(new Error('mock: background page gone'));
  await fireOnUpdated(h, 7, { url: 'https://example.com/again' }, state.activeTab);
  await drain();

  const allowed = new Set([
    'tabs',
    'tabs.query',
    'tabs.onUpdated',
    'tabs.onUpdated.addListener',
    'runtime',
    'runtime.sendMessage',
  ]);
  for (const touch of h.recorded.browserTouches) {
    assert.ok(
      allowed.has(touch),
      'popup.js touched a browser surface outside the pinned display-only ' +
        'boundary: browser.' + touch + ' (T034c §Analysis "Pinned ' +
        'surface" — the routing authority is the background; the popup ' +
        'originates no storage/proxy/privacy/notifications access)'
    );
  }
  for (const id of h.recorded.domLookups) {
    assert.strictEqual(
      id, 'route-indicator',
      'DOM lookups must target only the pinned indicator element; got "' +
        id + '" (T034c §Analysis "Pinned surface")'
    );
  }
  for (const w of h.recorded.elementWrites) {
    assert.strictEqual(
      w.id, 'route-indicator',
      'element writes must target only the pinned indicator element; got "' +
        w.id + '"'
    );
    assert.strictEqual(
      w.prop, 'textContent',
      'the label must be written via textContent — the injection-safe ' +
        'write; innerHTML on the indicator would be a script-insertion ' +
        'surface (T034c §Analysis "Pinned surface")'
    );
  }
  // Non-vacuousness: the flows actually exercised every recorded surface,
  // and exactly one onUpdated listener was registered (stacked listeners
  // would multiply re-renders).
  assert.ok(
    h.recorded.tabsQueries.length >= 1 &&
      h.recorded.messages.length >= 3 &&
      h.recorded.elementWrites.length >= 1,
    'the harness must have exercised query, asks, and a label write for ' +
      'this surface assertion to mean anything'
  );
  assert.strictEqual(
    h.recorded.onUpdatedListeners.length, 1,
    'exactly one tabs.onUpdated listener — duplicate registrations stack ' +
      'duplicate re-renders'
  );
  requireConformance(h.sandbox);
});

test('popupHtmlProvidesPinnedIndicatorElement', { skip: !htmlPresent() && HTML_ABSENT }, () => {
  const html = fs.readFileSync(POPUP_HTML_PATH, 'utf8');
  assert.match(
    html, /id="route-indicator"/,
    'popup.html must provide the pinned indicator element ' +
      '(id="route-indicator") — popup.js writes the label there ' +
      '(T034c §Analysis "Pinned surface"); id drift is a CI-caught ' +
      'contract break in either direction'
  );
});


test('lateTorReplyCannotOverwriteNewerUnknownRefresh', async () => {
  let resolveOld;
  const state = {
    activeTab: { id: 7 },
    reply: () => new Promise((resolve) => { resolveOld = resolve; }),
  };
  const h = loadPopup(state);
  await drain();
  state.reply = () => Promise.reject(new Error('background unavailable'));
  await fireOnUpdated(h, 7, { status: 'loading' }, state.activeTab);
  resolveOld({ route: 'tor' });
  await drain();
  assert.strictEqual(renderedLabel(h), LABEL_UNKNOWN);
});

test('refreshClearsTorWhileTheNewDecisionIsUnreadable', async () => {
  let resolveNew;
  const state = { activeTab: { id: 7 }, reply: () => Promise.resolve({ route: 'tor' }) };
  const h = loadPopup(state);
  await drain();
  assert.strictEqual(renderedLabel(h), LABEL_TOR);
  state.reply = () => new Promise((resolve) => { resolveNew = resolve; });
  await fireOnUpdated(h, 7, { status: 'loading' }, state.activeTab);
  assert.strictEqual(renderedLabel(h), LABEL_UNKNOWN);
  resolveNew({ route: 'unrouted' });
  await drain();
  assert.strictEqual(renderedLabel(h), LABEL_DIRECT);
});
