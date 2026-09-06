// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// router.js — the extension's per-request routing authority: the
// `browser.proxy.onRequest` listener implementing the canonical
// `.onion`→127.0.0.1:8881 SOCKS5 rule (FR-001) with the FR-002
// username/password wiring, the FR-003 `proxyDNS` flag, and the
// FR-004(b) fail-closed gate (as amended by T091) — plus the background
// half of the T034c-pinned per-tab indicator transport: the
// `webRequest.onBeforeRequest` decision cache and the `runtime.onMessage`
// responder the popup (T057) queries with
// `{type:'stargate:getRoute', tabId}`.
//
// Fail-closed matrix (FR-004(b); Constitution III): the SOCKS descriptor
// requires ALL of — the hardening gate open (`hardeningOk === true`,
// T055's flag; manifest M4 pins hardening.js loads before this script),
// an `.onion` request host, a non-throwing `firstPartyDomain`
// computation (a FirstPartyError governing URL never yields a guessed or
// empty username — the shared-circuit collapse T034d finding 3 forbids),
// and a present mirrored bearer token. Every unmet condition returns
// `{type:'direct'}` and records the tab as `unrouted`, so the popup's
// fail-closed label is the truth (the wrong-positive case T034c forbids).
//
// Non-`.onion` hosts get no proxy in this feature (FR-001 scope clause).
// `failoverTimeout` is intentionally NOT set — Firefox's default applies;
// pinning it would create a magic number with no spec-level rationale
// (tasks.md T054; spec assumption "proxy.onRequest failover timeout").
//
// The bearer token is MIRRORED into memory: read once at script
// evaluation (hardening.js load-time-async precedent) and refreshed on
// `storage.onChanged` for the device key. The sync mirror is what lets
// the T034c-pinned cache write happen in the synchronous onBeforeRequest
// listener — a per-request storage read could not know token presence
// synchronously, and an onion tab with no token configured would cache
// `tor` and the popup would lie. Descriptor and cache entry always read
// the same memory cell, so they can never disagree. Token FORMAT
// validation stays at the options edge (T052 §Analysis, data-model.md §5);
// the router checks only presence.
//
// Surface (T034g doctrine — firstparty.js / storage.js / hardening.js /
// router.js share ONE background-page global scope): this module
// contributes ZERO new globals — everything lives inside this IIFE; its
// surface is its four browser registrations, pinned by router.test.js.

'use strict';

(function stargateRouter() {
  // FR-001/FR-005: port 8881 is fixed to the Tor route in this feature.
  const TOR_HOST = '127.0.0.1';
  const TOR_PORT = 8881;
  const DIRECT = { type: 'direct' };
  const GET_ROUTE = 'stargate:getRoute';

  // The mirrored bearer token (FR-002 password). `null` = no token —
  // genuine unconfigured state, never fabricated (T052 storage.js
  // contract); `null` fails the gate closed.
  let mirroredToken = null;

  function refreshMirror() {
    return StargateStorage.getDevice()
      .then((device) => {
        mirroredToken =
          device !== null && typeof device === 'object' &&
          typeof device.bearerToken === 'string' && device.bearerToken !== ''
            ? device.bearerToken
            : null;
      })
      .catch(() => {
        // A broken storage read must degrade to fail-closed, never to a
        // rejection on the background page.
        mirroredToken = null;
      });
  }

  // The complete routing decision for one request. Pure over (details,
  // hardeningOk, mirroredToken) — evaluated by BOTH the cache writer and
  // the descriptor producer so the popup feed and the proxy can never
  // disagree on the same state.
  function route(details) {
    if (hardeningOk !== true) return { routed: false };
    let host;
    try {
      host = new URL(details.url).hostname;
    } catch {
      return { routed: false };
    }
    // One trailing dot is the FQDN form of a legal host; strip it so it
    // can neither evade the suffix check nor leak into the username
    // (mirrors firstparty.js normalization).
    host = host.replace(/\.$/, '');
    if (!host.endsWith('.onion')) return { routed: false };
    let username;
    try {
      username = firstPartyDomain(details);
    } catch {
      return { routed: false };
    }
    if (mirroredToken === null) return { routed: false };
    return { routed: true, username };
  }

  browser.proxy.onRequest.addListener(function proxyOnRequest(details) {
    const decision = route(details);
    if (!decision.routed) return DIRECT;
    return {
      type: 'socks',
      host: TOR_HOST,
      port: TOR_PORT,
      username: decision.username,
      password: mirroredToken,
      proxyDNS: true,
    };
  });

  // Per-tab decision cache (T034c §Analysis finding 1: "written by the
  // router's webRequest.onBeforeRequest listener"). Keyed by tabId;
  // non-tab requests (tabId -1) have no indicator and are not recorded.
  // The cache is bounded by the event-page lifetime: Firefox tears down
  // the non-persistent background page on idle, resetting script state.
  const tabDecisions = new Map();

  browser.webRequest.onBeforeRequest.addListener(
    function stargateOnBeforeRequest(details) {
      if (
        typeof details.tabId === 'number' &&
        Number.isInteger(details.tabId) &&
        details.tabId >= 0
      ) {
        tabDecisions.set(details.tabId, route(details).routed ? 'tor' : 'unrouted');
      }
      return {};
    },
    { urls: ['<all_urls>'] }
  );

  // The popup's query (T034c pinned protocol): `{route:'tor'}` iff the
  // cache holds a confirmed Tor decision; `{route:'unrouted'}` for a
  // recorded non-Tor decision; a Promise resolving `undefined` for an
  // unknown tab (cold start — "nothing meaningful"). The answer leaves
  // via the RESPONSE CHANNEL — a Promise return — because Firefox's
  // runtime.onMessage discards any other listener return value
  // ("The listener function can return either a Boolean or a Promise",
  // MDN; round-1 review Major): a plain object would make every popup
  // render its fail-closed label. Non-owned or malformed messages get a
  // plain `undefined` — not handled — so other listeners may answer
  // (the MDN multi-listener pattern: Promise only for messages this
  // listener handles).
  browser.runtime.onMessage.addListener(function stargateGetRoute(message) {
    if (message === null || typeof message !== 'object') return undefined;
    if (message.type !== GET_ROUTE) return undefined;
    const tabId = message.tabId;
    if (
      typeof tabId !== 'number' ||
      !Number.isInteger(tabId) ||
      tabId < 0
    ) {
      return undefined;
    }
    const decision = tabDecisions.get(tabId);
    if (decision === 'tor') return Promise.resolve({ route: 'tor' });
    if (decision === 'unrouted') return Promise.resolve({ route: 'unrouted' });
    return Promise.resolve(undefined);
  });

  // Token mirror upkeep: re-read when the device record changes (options
  // page save/removal, T056) and once at evaluation, below.
  browser.storage.onChanged.addListener(function stargateOnStorageChanged(
    changes,
    area
  ) {
    if (
      area === 'local' &&
      changes !== null &&
      typeof changes === 'object' &&
      Object.prototype.hasOwnProperty.call(changes, 'device')
    ) {
      refreshMirror();
    }
  });

  refreshMirror();
})();
