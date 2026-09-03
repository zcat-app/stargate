// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// options.test.js — Principle-VII unit test for the canonical
// `storage.local` warning text (FR-019; data-model.md §5.1).
//
// Three-replica drift gate (T034e §Analysis): data-model.md §5.1 is the
// single source of truth for the string; quickstart.md Step 4 and
// extension/options/options.html are replicas. The canonical string is
// always EXTRACTED from §5.1 (never hard-coded here — a fourth copy would
// defeat the single source of truth) and both replicas are asserted
// character-exact against it. The quote at quickstart Step 4 exists today,
// so that replica is gated from this commit; options.html is T056's
// artifact, so its case self-skips with a loud Principle-VII marker until
// the file exists, then bites inside T056's own verify run (T068a /
// T034b / T035a tests-first precedent).
//
// Unlike T034b there is no vm.runInNewContext() + `browser` mock here: the
// surface under test is static markup, not a script, so there is nothing
// to evaluate — what carries over is the discipline (node:test, Node
// built-ins only, no package.json, run-tests.sh discovery). "Rendered
// text" is modeled without a DOM by stripping comments and
// script/style elements, stripping tags, decoding the minimal entity set,
// and collapsing whitespace runs — the same normalization a browser
// applies, and the mirror image of markdown's soft-wrap join on the
// data-model side. data-model.md §5.1 pins the *rendered* string.

'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.join(__dirname, '..', '..');
const DATA_MODEL_PATH = path.join(REPO_ROOT, 'specs', '001-tor-route', 'data-model.md');
const QUICKSTART_PATH = path.join(REPO_ROOT, 'specs', '001-tor-route', 'quickstart.md');
const OPTIONS_HTML_PATH = path.join(__dirname, 'options.html');

const OPTIONS_ABSENT =
  'T056 not landed: extension/options/options.html does not exist yet ' +
  '(Principle-VII tests-first state; this case lifts and gates T056 when ' +
  'it lands — T068a/T034b/T035a precedent)';

const htmlPresent = () => fs.existsSync(OPTIONS_HTML_PATH);

// ---------------------------------------------------------------------------
// Markdown extraction. A section runs from its heading line to the next
// line at the same or shallower heading level; its canonical payload is
// the first blockquote (consecutive `>`-prefixed lines), soft-wrap joined
// with single spaces and whitespace-collapsed — exactly how a markdown
// renderer produces the rendered string.
// ---------------------------------------------------------------------------

function extractFirstBlockquoteAfterHeading(markdown, headingPrefix, fileLabel) {
  const lines = markdown.split('\n');
  const headingIndex = lines.findIndex((line) => line.startsWith(headingPrefix));
  assert.ok(
    headingIndex !== -1,
    fileLabel + ': heading not found — the spec section carrying the ' +
      'canonical string was removed or renamed. Expected a line starting ' +
      'with ' + JSON.stringify(headingPrefix) + '. This is loud-fail ' +
      'drift handling, never a silent pass (T034e §Acceptance #1/#2)'
  );
  const headingDepth = headingPrefix.match(/^#+/)[0].length;
  let sectionEnd = lines.length;
  for (let i = headingIndex + 1; i < lines.length; i += 1) {
    const nextHeading = lines[i].match(/^(#+) /);
    if (nextHeading && nextHeading[1].length <= headingDepth) {
      sectionEnd = i;
      break;
    }
  }
  const quoteLines = [];
  for (let i = headingIndex + 1; i < sectionEnd; i += 1) {
    const match = lines[i].match(/^> ?(.*)$/);
    if (!match) {
      if (quoteLines.length > 0) {
        break; // first blockquote ended
      }
      continue; // prose before the blockquote
    }
    quoteLines.push(match[1]);
  }
  assert.ok(
    quoteLines.length > 0,
    fileLabel + ': no blockquote found under the heading — the canonical ' +
      'string carrier is missing (loud fail, T034e §Analysis "no silent passes")'
  );
  return quoteLines.join(' ').replace(/\s+/g, ' ').trim();
}

function extractCanonicalFromDataModel() {
  return extractFirstBlockquoteAfterHeading(
    fs.readFileSync(DATA_MODEL_PATH, 'utf8'),
    '### 5.1 Canonical `storage.local` warning text',
    'data-model.md §5.1'
  );
}

function extractQuickstartQuote() {
  return extractFirstBlockquoteAfterHeading(
    fs.readFileSync(QUICKSTART_PATH, 'utf8'),
    '## Step 4 — Configure the bearer token in the extension',
    'quickstart.md Step 4'
  );
}

// ---------------------------------------------------------------------------
// Rendered-text modeling for options.html (no DOM, no third-party parser —
// research.md §10). Decode order matters: &amp; LAST, so a source-escaped
// "&amp;#39;" renders as the literal text "&#39;" rather than double-
// decoding into an apostrophe.
// ---------------------------------------------------------------------------

function renderedText(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style\s*>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

// Bounded preview for failure messages — the diff should name expected vs
// actual without dumping an arbitrarily large DOM into the assertion log.
function preview(text, max = 600) {
  return text.length <= max ? text : text.slice(0, max) + '…[' + (text.length - max) + ' more chars]';
}

test('canonicalStringIsPinnedInDataModelSection51', () => {
  const canonical = extractCanonicalFromDataModel();
  assert.match(
    canonical, /^Your bearer token will be saved /,
    'the §5.1 extraction must be the canonical warning, not neighboring prose'
  );
  assert.ok(canonical.includes('storage.local'), 'the warning names the storage path');
  assert.match(
    canonical, / credential-grade alternative for extensions\.$/,
    'the §5.1 extraction must be the full canonical string, not a prefix'
  );
  assert.doesNotMatch(
    canonical, /research\.md|THREAT-MODEL/i,
    'the user-facing string carries no doc cross-reference (data-model.md ' +
      '§5.1: "users see a clean factual notice, not a doc cross-reference")'
  );
});

test('quickstartStep4ReplicatesCanonicalStringByteForByte', () => {
  const canonical = extractCanonicalFromDataModel();
  const quickstartQuote = extractQuickstartQuote();
  assert.strictEqual(
    quickstartQuote, canonical,
    'quickstart.md Step 4 (replica c) drifted from data-model.md §5.1 (the ' +
      'source of truth). Resync the replica to §5.1 in the same PR — never ' +
      'edit one side silently (FR-019; data-model.md §5.1)'
  );
});

test('optionsHtmlRendersCanonicalStringByteForByte', { skip: !htmlPresent() && OPTIONS_ABSENT }, () => {
  const canonical = extractCanonicalFromDataModel();
  const rendered = renderedText(fs.readFileSync(OPTIONS_HTML_PATH, 'utf8'));
  assert.ok(
    rendered.includes(canonical),
    'options.html rendered text does not carry the data-model.md §5.1 ' +
      'canonical warning character-exact (FR-019; data-model.md §5.1: drift ' +
      'is a contract violation). Expected: ' + JSON.stringify(canonical) + '. ' +
      'Rendered text searched (comments/script/style already excluded): ' +
      JSON.stringify(preview(rendered))
  );
});
