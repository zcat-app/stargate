// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// firstparty.js — first-party-domain computation for the extension's
// SOCKS5 username (FR-002; architecture spec §14.3 step 1, extended by
// this feature's `.onion` rules). The return string IS the stream-
// isolation signal: Tor's IsolateSOCKSAuth (FR-011) turns distinct
// strings into distinct circuits, so a wrong string silently collapses
// unrelated origins onto one circuit — the failure mode every rule
// below exists to prevent (Constitution III).
//
// MV2 classic script (plan.md extension layout; research.md §10 — no
// build step, no third-party deps, no exports/wrapper). Loaded by the
// background page before router.js (T054) consumes it. Deliberately a
// PURE string function: zero browser.* access — router.js owns all API
// access (pinned by T034d finding 5).
//
// Contract (T034d §Analysis "Pinned surface" — the authorization
// boundary this module conforms to):
//   - Governing-URL precedence per arch §14.3 step 1: documentUrl,
//     then originUrl, then the request url.
//   - An ABSENT key is missing; a PRESENT-but-unparseable value — the
//     empty string included — throws the FirstPartyError sentinel,
//     never a routable fallback string (an empty-string username would
//     route every malformed-documentUrl request onto one shared
//     circuit; T034d finding 3).
//   - A `.onion` governing host is returned verbatim — onion addresses
//     are flat, no eTLD reduction (FR-002 `.onion` rule).
//   - A governing URL that parses but has NO host (about:, data:, blob:)
//     throws the sentinel — an empty host is no first-party at all, and
//     the empty-string username is the one routable string FR-002
//     forbids above all.
//   - IPv4 literals are flat like `.onion` (returned whole): a
//     last-two-labels reduction would put distinct addresses on one
//     shared circuit ('10.1.2.3' and '10.9.2.3' both reduce to '2.3').
//   - Any other host reduces to its eTLD+1, computed as the last two
//     dot-separated labels. Public-suffix nuance (.co.uk and friends)
//     is deliberately NOT computed: this feature routes `.onion` only,
//     and a public-suffix list would be a third-party dep the plan
//     forbids (T034d finding 4).

'use strict';

// Exactly one new global (T034d "Pinned surface": MV2 lib scripts all
// load into ONE background-page scope, so every extra top-level binding
// is a namespace-collision surface).
function firstPartyDomain(requestDetails) {
  // Sentinel for a present-but-unparseable governing URL. Only `name`
  // is pinned (`FirstPartyError`); the message is for router.js's
  // (T054) fail-closed surface. Message built without coercing `value`
  // to a string so a junk-typed input can never break the sentinel
  // itself.
  function sentinel(kind, value) {
    const err = new Error(
      'firstPartyDomain: present-but-unparseable ' + kind +
        ' (typeof ' + typeof value + ')' +
        ' — refusing to route under a guessed first-party (FR-002)'
    );
    err.name = 'FirstPartyError';
    return err;
  }

  // Governing URL per arch §14.3 step 1: documentUrl, then originUrl,
  // then the request url. An absent (undefined) key is missing
  // (T034d case (d)); a present non-string is malformed under the same
  // sentinel contract as an unparseable string.
  let governing = requestDetails.url;
  const preferred = [
    ['documentUrl', requestDetails.documentUrl],
    ['originUrl', requestDetails.originUrl],
  ];
  for (const [kind, value] of preferred) {
    if (typeof value === 'undefined') continue;
    if (typeof value !== 'string') throw sentinel(kind, value);
    governing = value;
    break;
  }

  let parsed;
  try {
    parsed = new URL(governing);
  } catch {
    throw sentinel('governing URL', governing);
  }

  // One trailing dot is the FQDN form of a legal host; strip it so it
  // can neither defeat the `.onion` suffix check nor yield a degenerate
  // label split.
  const host = parsed.hostname.replace(/\.$/, '');

  // A parseable-but-hostless governing URL (about:blank, data:, blob:,
  // file:) yields hostname '' — with no host there is no first-party to
  // isolate on, and the empty-string username is itself the forbidden
  // routable fallback that collapses unrelated origins onto one shared
  // circuit (T034d finding 3).
  if (host === '') throw sentinel('governing URL', governing);

  // `.onion` hosts are flat: the address itself is the first-party, no
  // reduction (FR-002 `.onion` rule; T034d cases (a)/(b)).
  if (host.endsWith('.onion')) return host;

  // IPv4 literals are flat like `.onion`, not registrable domains: the
  // last-two-labels reduction would collapse distinct addresses onto
  // shared circuits ('10.1.2.3' and '10.9.2.3' both reduce to '2.3').
  // All-numeric labels can never carry a public suffix, so returning
  // the literal whole is always the non-collapsing side.
  if (host.split('.').every(label => /^\d+$/.test(label))) return host;

  const labels = host.split('.');
  return labels.length >= 2
    ? labels[labels.length - 2] + '.' + labels[labels.length - 1]
    : host;
}
