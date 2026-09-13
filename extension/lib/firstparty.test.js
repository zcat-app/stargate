// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// firstparty.test.js — Principle-VII unit test for the extension's
// initiating-site computation (`lib/firstparty.js`, FR-002 and T136).
//
// Boundary under test (T034d §Analysis — the pinned surface): the module
// is a synchronous canonicalizer. It takes a `requestDetails`-shaped object
// (`url`; optional `documentUrl` / `originUrl`, absent keys meaning
// missing) and returns a type-tagged canonical site. Router.js combines
// that site with device and browser-profile identity before deriving the
// opaque SOCKS username. Onion addresses stay whole; DNS sites use Firefox
// 153's native ICANN-and-PRIVATE publicSuffix API. Present-but-
// unparseable `documentUrl`/`originUrl` throws the `FirstPartyError`
// sentinel — never a silent fallback to a wrong first-party, because a
// routable wrong string collapses unrelated origins onto one Tor
// circuit (`IsolateSOCKSAuth`, FR-011). The Tor-side circuit behaviour
// this signal drives is T058/T059/T061's, deliberately not duplicated
// here.
//
// The recording `browser.publicSuffix.getDomain` stub pins the only browser
// API this canonicalizer may use. Router.js still owns stateful APIs.
//
// MV2 lib scripts load as browser global scripts, not ES modules, so
// the test loads firstparty.js via vm.runInNewContext() with a
// synthesized sandbox (a recording native suffix authority, plus the host's
// WHATWG `URL` — spec-identical to the browser's — and `console`).
// No UMD wrapper or module shim is added to the extension (research.md
// §10). Node built-ins only — no third-party deps, no package.json.

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const FIRSTPARTY_PATH = path.join(__dirname, 'firstparty.js');
const IMPL_ABSENT =
  'T053 not landed: extension/lib/firstparty.js does not exist yet ' +
  '(Principle-VII tests-first state; these cases lift and gate T053 ' +
  'when it lands — T068a/T034b/T035a precedent)';

const implPresent = () => fs.existsSync(FIRSTPARTY_PATH);

// 56 base32 chars (a-z, 2-7) + `.onion` — syntactically plausible v3
// addresses; checksum validity is irrelevant to this canonicalization
// contract (T034d §Acceptance 3).
const ONION_A = 'abcd2345'.repeat(7) + '.onion';
const ONION_B = 'efgh6527'.repeat(7) + '.onion';

// ---------------------------------------------------------------------------
// Loader. Evaluates firstparty.js in a fresh context whose globals are
// exactly what T136 pins: a recording `browser.publicSuffix`, the host
// `URL`, and `console`. Nothing else — any further global the impl
// reaches for is a loud ReferenceError, which is the conformance signal.
// ---------------------------------------------------------------------------

function makeSandbox() {
  const browserTouches = [];
  const browser = {
    publicSuffix: {
      getDomain(...args) {
        const host = args[0];
        browserTouches.push(['publicSuffix.getDomain', ...args]);
        if (host === 'news.example.com') return 'example.com';
        return null;
      },
    },
  };
  return { sandbox: { browser, URL, console }, browserTouches };
}

function loadFirstParty() {
  const { sandbox, browserTouches } = makeSandbox();
  const source = fs.readFileSync(FIRSTPARTY_PATH, 'utf8');
  vm.runInNewContext(source, sandbox, { filename: 'lib/firstparty.js' });
  return { sandbox, browserTouches };
}

// Conformance gate: hard-fail (not skip) when firstparty.js exists but
// does not expose the pinned surface — a silent re-skip here would let
// T053 ship ungated (T034d §Analysis "Pinned surface").
function requireConformance(sandbox) {
  assert.ok(
    typeof sandbox.firstPartyDomain === 'function',
    'pinned surface violated: expected a context global function ' +
      '`firstPartyDomain(requestDetails)` (T034d §Analysis; FR-002; ' +
      'arch §14.3 step 1). Got: ' + typeof sandbox.firstPartyDomain
  );
  // Surface exclusivity (T034d §Analysis "exactly one new global";
  // T034d round-1 verdict FINDINGS[1]): lib/firstparty.js,
  // background/router.js, background/hardening.js and lib/storage.js
  // all load as classic scripts into ONE background-page global scope,
  // so an extra top-level `var` is a namespace-collision surface the
  // pin promises to gate.
  const extraGlobals = Object.keys(sandbox).filter(
    (name) => name !== 'browser' && name !== 'URL' && name !== 'console'
  );
  assert.deepStrictEqual(
    extraGlobals.sort(),
    ['firstPartyDomain'],
    'pinned surface violated: expected exactly one function; got [' +
      extraGlobals.join(', ') + '] ' +
      '(T034d §Analysis "Pinned surface"; FR-002; MV2 classic scripts ' +
      'share one background-page global scope — an extra top-level ' +
      'global is a namespace-collision surface)'
  );
}

const skip = () => (!implPresent() ? IMPL_ABSENT : false);

test('onionTopLevelNavigationReturnsOnionAddressVerbatim', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  // Top-level navigation: documentUrl IS the onion address; originUrl
  // absent (body case (a)).
  const details = {
    url: `http://${ONION_A}/`,
    type: 'main_frame',
    frameId: 0,
  };
  assert.strictEqual(
    sandbox.firstPartyDomain(details), `onion:${ONION_A}`,
    'a top-level .onion navigation returns the onion address itself — ' +
      'no eTLD reduction on .onion (FR-002 .onion rule; onion addresses are flat)'
  );
});

test('onionSubresourceBindsToParentDocumentOnion', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  // Subresource fetch inside an onion document hosted at ONION_A; the
  // fetch targets a different onion CDN (body case (b)).
  const details = {
    url: `http://${ONION_B}/cdn/jquery.js`,
    documentUrl: `http://${ONION_A}/page`,
    type: 'script',
    frameId: 0,
  };
  assert.strictEqual(
    sandbox.firstPartyDomain(details), `onion:${ONION_A}`,
    'a subresource of a .onion document carries the document\'s onion as ' +
      'its first-party, never the subresource\'s own host (FR-002 subresource rule)'
  );
});

test('clearnetDocumentUrlReducesToEtldPlusOne', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  // Clearnet pass-through correctness for later features' Direct/Mixnet
  // routes (body case (c); arch §14.3 step 1).
  const details = {
    url: 'https://news.example.com/img.png',
    documentUrl: 'https://news.example.com/article',
    type: 'image',
    frameId: 0,
  };
  assert.strictEqual(
    sandbox.firstPartyDomain(details), 'dns:example.com',
    'a clearnet documentUrl host reduces to its eTLD+1 (arch §14.3 step 1)'
  );
});

test('onlyMainFrameMayUseRequestUrlAsInitiatingSite', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  assert.strictEqual(
    sandbox.firstPartyDomain({
      url: 'https://news.example.com/',
      type: 'main_frame',
      frameId: 0,
    }),
    'dns:example.com',
    'a top-level navigation defines its new initiating site'
  );
  assert.throws(
    () => sandbox.firstPartyDomain({
      url: `https://${ONION_A}/asset.js`,
      type: 'script',
      frameId: 0,
    }),
    (err) => !!err && err.name === 'FirstPartyError',
    'a subresource with no top-level document context must not use its ' +
      'destination as the isolation site (Constitution III/T136)'
  );
});

test('distinctOnionsYieldDistinctFirstPartyStrings', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  const firstA = sandbox.firstPartyDomain({
    url: `http://${ONION_A}/`,
    type: 'main_frame',
    frameId: 0,
  });
  const firstB = sandbox.firstPartyDomain({
    url: `http://${ONION_B}/`,
    type: 'main_frame',
    frameId: 0,
  });
  assert.strictEqual(typeof firstA, 'string', 'the first-party is a string (the SOCKS5 username FR-002 mandates)');
  assert.notStrictEqual(
    firstA, firstB,
    'distinct onion addresses MUST yield distinct username strings — the ' +
      'FR-002 invariant IsolateSOCKSAuth (FR-011) turns into distinct circuits'
  );
});

test('sameOnionAcrossRequestsYieldsEqualFirstPartyStrings', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  // Two distinct requests into the same onion document (different pages,
  // different subresources) — the same-origin shared-circuit case from
  // US2 acceptance scenario 3 (body case (f)).
  const first1 = sandbox.firstPartyDomain({
    url: `http://${ONION_A}/assets/x.png`,
    documentUrl: `http://${ONION_A}/page`,
    type: 'image',
    frameId: 0,
  });
  const first2 = sandbox.firstPartyDomain({
    url: `http://${ONION_A}/assets/y.png`,
    documentUrl: `http://${ONION_A}/other`,
    type: 'image',
    frameId: 0,
  });
  assert.strictEqual(
    first1, first2,
    'the same onion across distinct requests yields equal username strings — ' +
      'the equality is the signal for Tor to reuse a circuit (US2 scenario 3)'
  );
});

test('malformedDocumentUrlThrowsSentinelNeverSilentFallback', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  // Present-but-unparseable documentUrl: the empty string is MALFORMED,
  // not missing (T034d §Analysis finding 3 — treating it as missing
  // would be the silent wrong-first-party fallback case (g) forbids).
  // The pinned shape is the throw sentinel; `''`, garbage text, and a
  // scheme-only string must all fail the same way — consistently.
  const malformed = ['', 'not a url', 'http://'];
  for (const bad of malformed) {
    assert.throws(
      () => sandbox.firstPartyDomain({
        url: `http://${ONION_A}/`,
        documentUrl: bad,
        type: 'image',
        frameId: 0,
      }),
      // Duck-typed on `name`, deliberately NOT `instanceof Error`: the
      // sentinel is thrown from inside the vm context, whose Error is a
      // different realm's constructor — a host-realm instanceof check
      // rejects a genuinely conforming sentinel (first falsification
      // round found exactly that).
      (err) => !!err && err.name === 'FirstPartyError',
      `present-but-unparseable documentUrl (${JSON.stringify(bad)}) must throw ` +
        'the FirstPartyError sentinel — never a routable fallback string ' +
        '(T034d §Analysis finding 3; body case (g))'
    );
  }
});

test('firstPartyModuleUsesOnlyNativePublicSuffixApiForDns', { skip: skip() }, () => {
  const { sandbox, browserTouches } = loadFirstParty();
  requireConformance(sandbox);
  // Every canonical input from cases (a)-(g) through one fresh context;
  // Only the clearnet DNS case reaches the native suffix authority. Onion,
  // missing and malformed contexts are handled locally.
  const canonical = [
    { url: `http://${ONION_A}/`, type: 'main_frame', frameId: 0 },
    { url: `http://${ONION_B}/cdn/jquery.js`, documentUrl: `http://${ONION_A}/page`, type: 'script', frameId: 0 },
    { url: 'https://news.example.com/img.png', documentUrl: 'https://news.example.com/article', type: 'image', frameId: 0 },
    { url: 'https://news.example.com/assets/app.js', type: 'script', frameId: 0 },
    { url: `http://${ONION_A}/`, documentUrl: '', type: 'image', frameId: 0 },
  ];
  for (const details of canonical) {
    try {
      sandbox.firstPartyDomain(details);
    } catch (err) {
      // Expected for the malformed entry; the assertion below is the point.
    }
  }
  assert.deepStrictEqual(
    browserTouches, [['publicSuffix.getDomain', 'news.example.com']],
    'firstparty.js may touch only the Firefox 153 native suffix authority'
  );
});
