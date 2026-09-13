// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// firstparty.edges.test.js — edge-guard evidence for `lib/firstparty.js`,
// added in T053 round-2 REWORK. The frozen T034d suite cannot reach the
// two fail-closed guards below: its case-(g) inputs (`''`, `'not a url'`,
// `'http://'`) all die at `new URL()` parsing — none reaches the
// parses-but-hostless branch — and no suite input is an IP literal
// (r1-review Major finding; Principle VII — for privacy-critical code
// the test IS the executable spec, so a guard no test can fail on is
// unpinned). This file pins them without touching firstparty.test.js
// (T034d frontmatter: "must NOT edit this test") or the runner —
// run-tests.sh auto-discovers every *.test.js.
//
// The sandbox supplies deterministic native-suffix results; the main suite
// separately pins that this is the only browser API touched. This file's
// subject is reachability of the guards. If firstparty.js is absent
// the read below fails loudly — correct: this suite ships in the same
// commit as the impl, unlike the tests-first frozen suite.

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const FIRSTPARTY_PATH = path.join(__dirname, 'firstparty.js');

// Same 56-char v3-shaped address as the frozen suite — checksum
// validity is irrelevant to this pure-logic contract (T034d §Acceptance 3).
const ONION_A = 'abcd2345'.repeat(7) + '.onion';

function loadFirstParty() {
  const domains = new Map([
    ['www.alice.co.uk', 'alice.co.uk'],
    ['alice.github.io', 'alice.github.io'],
    ['bob.github.io', 'bob.github.io'],
    ['a.b.ck', 'a.b.ck'],
    ['x.www.ck', 'www.ck'],
    ['co.uk', null],
    ['www.xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn'],
  ]);
  const sandbox = {
    browser: {
      publicSuffix: {
        getDomain(host) {
          return domains.has(host) ? domains.get(host) : null;
        },
      },
    },
    URL,
    console,
  };
  vm.runInNewContext(
    fs.readFileSync(FIRSTPARTY_PATH, 'utf8'),
    sandbox,
    { filename: 'lib/firstparty.js' }
  );
  assert.strictEqual(
    typeof sandbox.firstPartyDomain, 'function',
    'pinned surface violated: expected global `firstPartyDomain` (T034d §Analysis)'
  );
  return sandbox;
}

test('hostlessGoverningUrlThrowsSentinelNeverRoutableFallback', () => {
  const { firstPartyDomain } = loadFirstParty();
  // A governing URL that PARSES but carries no host. Firefox webRequest
  // produces exactly these documentUrl values for subresources of
  // about:/data:/blob: documents — the module's trust edge. Deleting the
  // `host === ''` guard makes each call return `''` — the one ROUTABLE
  // string the contract forbids above all: it collapses every
  // hostless-document subrequest across all sites onto one shared
  // circuit (T034d finding 3; r1-review mutation demo: zero frozen-suite
  // tests failed with the guard deleted).
  const hostless = [
    'about:blank',
    'data:text/html,hi',
    'blob:https://example.com/x',
  ];
  for (const governing of hostless) {
    assert.throws(
      () => firstPartyDomain({
        url: `http://${ONION_A}/`,
        documentUrl: governing,
        type: 'image',
        frameId: 0,
      }),
      // Duck-typed on `name`, not `instanceof Error`: the sentinel is
      // thrown from inside the vm context, whose Error is another
      // realm's constructor (frozen suite, falsification round 1).
      (err) => !!err && err.name === 'FirstPartyError',
      `hostless governing URL (${JSON.stringify(governing)}) must throw the ` +
        'FirstPartyError sentinel — never a routable fallback string ' +
        '(T034d finding 3; FR-002; Constitution III)'
    );
  }
});

test('ipv4LiteralGoverningHostsReturnWholeAndStayDistinct', () => {
  const { firstPartyDomain } = loadFirstParty();
  // Deleting the all-numeric-labels branch sends both addresses through
  // the two-label reduction → both '2.3': distinct addresses on one
  // shared circuit, the collision the ticket Analysis documents. No
  // frozen-suite input is an IP literal, so only this test bites.
  const a = firstPartyDomain({
    url: 'http://10.1.2.3/x', type: 'main_frame', frameId: 0,
  });
  const b = firstPartyDomain({
    url: 'http://10.9.2.3/y', type: 'main_frame', frameId: 0,
  });
  assert.strictEqual(
    a, 'ipv4:10.1.2.3',
    'an IPv4-literal governing host is flat — returned whole, like .onion ' +
      '(all-numeric labels can never carry a public suffix)'
  );
  assert.strictEqual(
    b, 'ipv4:10.9.2.3',
    'an IPv4-literal governing host is flat — returned whole, like .onion'
  );
  assert.notStrictEqual(
    a, b,
    'distinct IPv4 literals MUST yield distinct username strings — ' +
      'IsolateSOCKSAuth (FR-011) turns the string into circuit identity; ' +
      'both reduce to \'2.3\' without the guard (Constitution III)'
  );
});

test('multiLabelOnionGoverningHostReturnsWholeAddress', () => {
  const { firstPartyDomain } = loadFirstParty();
  // The `.onion` early-return is indistinguishable from the two-label
  // reduction on every frozen-suite onion (each is exactly
  // `label + '.onion'`); a dotted onion-adjacent host makes the branch
  // observable (r1-review informational item c). Without the early
  // return this host would reduce to `abcd2345.onion` — not the
  // address the request actually targeted.
  const host = 'sub.' + ONION_A;
  assert.strictEqual(
    firstPartyDomain({
      url: `http://${host}/`,
      type: 'main_frame',
      frameId: 0,
    }),
    `onion:${host}`,
    'a multi-label .onion governing host returns whole — onion addresses ' +
      'are flat, no eTLD reduction (FR-002 .onion rule)'
  );
});

test('nativePublicPrivateWildcardAndExceptionResultsAreTypeTagged', () => {
  const { firstPartyDomain } = loadFirstParty();
  const top = (url) => firstPartyDomain({
    url, type: 'main_frame', frameId: 0,
  });

  assert.strictEqual(top('https://www.alice.co.uk/'), 'dns:alice.co.uk');
  assert.strictEqual(top('https://alice.github.io/'), 'dns:alice.github.io');
  assert.strictEqual(top('https://bob.github.io/'), 'dns:bob.github.io');
  assert.strictEqual(top('https://a.b.ck/'), 'dns:a.b.ck');
  assert.strictEqual(top('https://x.www.ck/'), 'dns:www.ck');
  assert.throws(
    () => top('https://a.example.unknown-t136/'),
    (err) => !!err && err.name === 'FirstPartyError',
    'unknown suffixes remain unavailable; allowUnknownSuffix is never enabled'
  );
  assert.throws(
    () => top('https://co.uk/'),
    (err) => !!err && err.name === 'FirstPartyError',
    'a public suffix without a registrable label is not an initiating site'
  );
});

test('idnaSchemePortAndIpCanonicalizationIsDeterministic', () => {
  const { firstPartyDomain } = loadFirstParty();
  const top = (url) => firstPartyDomain({
    url, type: 'main_frame', frameId: 0,
  });

  assert.strictEqual(
    top('https://www.食狮.公司.cn:8443/path?x=1'),
    'dns:xn--85x722f.xn--55qx5d.cn'
  );
  assert.strictEqual(
    top('http://WWW.食狮.公司.CN./other'),
    'dns:xn--85x722f.xn--55qx5d.cn',
    'scheme, port, case and one terminal FQDN dot do not change the site'
  );
  assert.strictEqual(top('http://0300.0x0.0.1/'), 'ipv4:192.0.0.1');
  assert.strictEqual(top('https://[2001:0db8:0:0::1]:444/'), 'ipv6:[2001:db8::1]');
  for (const url of ['ftp://example.com/x', 'about:blank', 'data:text/plain,x']) {
    assert.throws(
      () => top(url),
      (err) => !!err && err.name === 'FirstPartyError',
      `unsupported or opaque top-level URL ${url} has no routable site`
    );
  }
});

test('nativeSuffixFailureAndUnexpectedResultAreUnavailable', () => {
  for (const getDomain of [
    () => undefined,
    () => { throw new Error('synthetic native suffix failure'); },
  ]) {
    const sandbox = {
      browser: { publicSuffix: { getDomain } },
      URL,
      console,
    };
    vm.runInNewContext(fs.readFileSync(FIRSTPARTY_PATH, 'utf8'), sandbox);
    assert.throws(
      () => sandbox.firstPartyDomain({
        url: 'https://www.example.com/', type: 'main_frame', frameId: 0,
      }),
      (err) => !!err && err.name === 'FirstPartyError'
    );
  }
});
