// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// firstparty.test.js — Principle-VII unit test for the extension's
// first-party-domain computation (`lib/firstparty.js`, FR-002;
// architecture spec §14.3 step 1 as extended by this feature's
// `.onion` rules).
//
// Boundary under test (T034d §Analysis — the pinned surface): the module
// is a pure string function. It takes a `requestDetails`-shaped object
// (`url`; optional `documentUrl` / `originUrl`, absent keys meaning
// missing) and returns the SOCKS5 username string FR-002 mandates:
// the onion address verbatim for `.onion` (onion addresses are flat —
// no eTLD reduction), otherwise the governing URL's eTLD+1, with
// `documentUrl` governing over the request `url`. Present-but-
// unparseable `documentUrl`/`originUrl` throws the `FirstPartyError`
// sentinel — never a silent fallback to a wrong first-party, because a
// routable wrong string collapses unrelated origins onto one Tor
// circuit (`IsolateSOCKSAuth`, FR-011). The Tor-side circuit behaviour
// this signal drives is T058/T059/T061's, deliberately not duplicated
// here.
//
// The empty `browser` global the body prescribes is itself an
// assertion: the sandbox's `browser` is an access-recording empty
// object, and firstPartyModuleNeverTouchesBrowserApis pins zero touches
// — router.js (T054) owns all API access; if firstparty.js ever reads
// `browser.storage` rules directly, the router-composition assumption
// is false and this suite catches it.
//
// MV2 lib scripts load as browser global scripts, not ES modules, so
// the test loads firstparty.js via vm.runInNewContext() with a
// synthesized sandbox (`browser` recording-empty, plus the host's
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
// addresses; checksum validity is irrelevant to this pure-logic
// contract (T034d §Acceptance 3).
const ONION_A = 'abcd2345'.repeat(7) + '.onion';
const ONION_B = 'efgh6527'.repeat(7) + '.onion';

// ---------------------------------------------------------------------------
// Loader. Evaluates firstparty.js in a fresh context whose globals are
// exactly what T034d §Analysis pins: a recording-empty `browser`, the
// host `URL`, and `console`. Nothing else — any further global the impl
// reaches for is a loud ReferenceError, which is the conformance signal.
// ---------------------------------------------------------------------------

function makeSandbox() {
  const browserTouches = [];
  const browser = new Proxy({}, {
    get(_target, prop) {
      browserTouches.push(String(prop));
      return undefined;
    },
    has() {
      browserTouches.push('[[has]]');
      return false;
    },
  });
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
}

const skip = () => (!implPresent() ? IMPL_ABSENT : false);

test('onionTopLevelNavigationReturnsOnionAddressVerbatim', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  // Top-level navigation: documentUrl IS the onion address; originUrl
  // absent (body case (a)).
  const details = {
    url: `http://${ONION_A}/`,
    documentUrl: `http://${ONION_A}/`,
  };
  assert.strictEqual(
    sandbox.firstPartyDomain(details), ONION_A,
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
  };
  assert.strictEqual(
    sandbox.firstPartyDomain(details), ONION_A,
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
  };
  assert.strictEqual(
    sandbox.firstPartyDomain(details), 'example.com',
    'a clearnet documentUrl host reduces to its eTLD+1 (arch §14.3 step 1)'
  );
});

test('missingDocumentAndOriginUrlsFallBackToRequestEtldPlusOne', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  // documentUrl and originUrl keys ABSENT — the (d) fallback; contrast
  // with present-but-malformed in
  // malformedDocumentUrlThrowsSentinelNeverSilentFallback.
  const details = { url: 'https://news.example.com/assets/app.js' };
  assert.strictEqual(
    sandbox.firstPartyDomain(details), 'example.com',
    'with documentUrl and originUrl both absent, the request url\'s ' +
      'eTLD+1 is the fallback (arch §14.3 step 1)'
  );
});

test('distinctOnionsYieldDistinctFirstPartyStrings', { skip: skip() }, () => {
  const { sandbox } = loadFirstParty();
  requireConformance(sandbox);
  const firstA = sandbox.firstPartyDomain({
    url: `http://${ONION_A}/`,
    documentUrl: `http://${ONION_A}/`,
  });
  const firstB = sandbox.firstPartyDomain({
    url: `http://${ONION_B}/`,
    documentUrl: `http://${ONION_B}/`,
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
  });
  const first2 = sandbox.firstPartyDomain({
    url: `http://${ONION_A}/assets/y.png`,
    documentUrl: `http://${ONION_A}/other`,
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

test('firstPartyModuleNeverTouchesBrowserApis', { skip: skip() }, () => {
  const { sandbox, browserTouches } = loadFirstParty();
  requireConformance(sandbox);
  // Every canonical input from cases (a)-(g) through one fresh context;
  // the recording `browser` must report zero property touches. Malformed
  // inputs throw — swallowing here is fine: the purity property is about
  // API access, not about the outcome.
  const canonical = [
    { url: `http://${ONION_A}/`, documentUrl: `http://${ONION_A}/` },
    { url: `http://${ONION_B}/cdn/jquery.js`, documentUrl: `http://${ONION_A}/page` },
    { url: 'https://news.example.com/img.png', documentUrl: 'https://news.example.com/article' },
    { url: 'https://news.example.com/assets/app.js' },
    { url: `http://${ONION_A}/`, documentUrl: '' },
  ];
  for (const details of canonical) {
    try {
      sandbox.firstPartyDomain(details);
    } catch (err) {
      // Expected for the malformed entry; the assertion below is the point.
    }
  }
  assert.deepStrictEqual(
    browserTouches, [],
    'firstparty.js must be a pure string function — zero browser.* API ' +
      'touches (T034d §Analysis finding 5; router.js T054 owns all API access)'
  );
});
