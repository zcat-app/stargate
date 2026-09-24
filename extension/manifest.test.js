// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// manifest.test.js — Principle-VII schema gate for extension/manifest.json
// (T051). The manifest IS the extension's privacy-surface declaration, so
// the properties pinned here are the ticket's §Analysis must-holds M1–M7:
//
//   M1  Manifest V2 with identity keys (arch §14.1; research.md §2 — MV2 is
//       the carrier of the per-request SOCKS5 username, FR-002)
//   M2  permission set EXACTLY arch §14.2 + T091/T136 — bidirectional set
//       equality, so none missing AND none extra (§14.2: no tabs, history,
//       bookmarks, cookies, identity; `management` is the T091-amended
//       contract, T091 acceptance #5: "T051 must request management")
//   M3  persistent MV2 routing authority (T157 startup-race boundary)
//   M4  background script list exact; hardening.js BEFORE router.js —
//       proxy.onRequest must not be registered before the FR-004 gate flag
//       exists (arch §14.5 Part 2)
//   M5  browser_specific_settings.gecko.id well-formed and Firefox 153+
//   M6  options_ui / browser_action registered at the T056/T057 pinned
//       paths (registration lives here so the sibling tickets never amend
//       this file — T051 §Analysis W2)
//   M7  strict JSON — consumed verbatim by Firefox and package.sh
//
// Reads the real file from disk — no fixture (a mocked manifest would test
// this suite against itself). Node built-ins only, node:test runner
// (research.md §10). Registered collaborators (lib/, background/, options/,
// popup/) are authored by T052–T057 and are intentionally NOT asserted to
// exist here — that is assembly-time (T051 §Analysis residue R1), not a
// parallel-ticket gate.

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');

const MANIFEST_PATH = path.join(__dirname, 'manifest.json');

const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));

test('M1: manifest_version is 2 with name/version identity keys', () => {
  assert.strictEqual(manifest.manifest_version, 2);
  // Firefox-required identity keys; folding them into M1 shrinks residue R2
  // (no web-ext schema validator runs in CI — research.md §10) by the two
  // loadability properties v1 cares about beyond the named surface.
  assert.strictEqual(typeof manifest.name, 'string');
  assert.ok(manifest.name.trim().length > 0, 'name must be non-empty');
  assert.strictEqual(typeof manifest.version, 'string');
  assert.match(manifest.version, /^\d+(\.\d+){0,3}$/);
});

test('M2: permission set is exactly §14.2 + T091/T136 (bidirectional)', () => {
  // Sorted both sides: deepStrictEqual over sorted arrays is set equality —
  // a dropped permission fails (body/T091 contract) and a sneaked one fails
  // too (§14.2 exclusion clause; a permission is unbounded privacy surface).
  const required = [
    'proxy',
    'storage',
    'webNavigation',
    'webRequest',
    'webRequestBlocking',
    'privacy',
    'publicSuffix',
    'notifications',
    'management',
    '<all_urls>',
  ].sort();
  const actual = [...manifest.permissions].sort();
  assert.deepStrictEqual(actual, required);
});

test('M3: background routing authority persists across protected requests', () => {
  assert.strictEqual(manifest.background?.persistent, true);
});

test('M4: background scripts exact; hardening.js before router.js', () => {
  const expected = [
    'lib/firstparty.js',
    'lib/storage.js',
    'background/hardening.js',
    'background/router.js',
  ];
  assert.deepStrictEqual(manifest.background?.scripts, expected);
  // Named separately so a reorder fails with the privacy reason, not just
  // an array diff (arch §14.5 Part 2 / FR-004 fail-closed).
  const scripts = manifest.background.scripts;
  assert.ok(
    scripts.indexOf('background/hardening.js') <
      scripts.indexOf('background/router.js'),
    'hardening.js must load before router.js: the FR-004 gate flag must exist before proxy.onRequest can serve a non-Direct route'
  );
});

test('M5: gecko id is well-formed and Firefox 153 is the minimum', () => {
  const gecko = manifest.browser_specific_settings?.gecko;
  const id = gecko?.id;
  assert.strictEqual(typeof id, 'string');
  assert.ok(id.length > 0, 'gecko id must be non-empty');
  // Firefox accepts a GUID in braces or an email-like identifier.
  assert.ok(
    /^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$/.test(
      id
    ) ||
      /^[a-zA-Z0-9-._]+@[a-zA-Z0-9-._]+$/.test(id),
    `gecko id must be a GUID or email-like string, got ${JSON.stringify(id)}`
  );
  assert.strictEqual(
    gecko.strict_min_version,
    '153.0',
    'publicSuffix and document-bound proxy metadata require Firefox 153+'
  );
});

test('M6: options_ui and browser_action registered at pinned paths', () => {
  assert.strictEqual(manifest.options_ui?.page, 'options/options.html');
  assert.strictEqual(manifest.browser_action?.default_popup, 'popup/popup.html');
});
