// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// popup.js — the browser-action popup's per-tab route indicator (T057;
// the observable surface of US1 acceptance scenario 1). Displays the
// routing decision the background (router.js, T054) recorded for the
// ACTIVE tab in its `webRequest.onBeforeRequest` cache, fetched live
// over the T034c-pinned protocol:
// `runtime.sendMessage({type:'stargate:getRoute', tabId})`.
//
// The popup never decides routing from the tab URL: the background's
// decision (host rule, hardening gate, token presence) is the single
// authority, and a second client-side rule could silently disagree
// with it (T057 §Analysis finding 4).
//
// Fail-closed display mapping (Constitution V; T034c must-hold 1) —
// harm is asymmetric, so the mapping is exact: `Route: Tor` IFF the
// live reply is an object with `route === 'tor'`; every absent,
// malformed, unrecognizable, or failed answer renders the safe default
// `Route: Direct (unrouted)`. A wrong-positive tells the user they are
// routed when they are not; a wrong-negative is mere annoyance.
//
// Surface (T034c §"Pinned surface" — the conformance gate in
// popup.test.js): zero new context globals (one named IIFE); renders
// at load (popup.html loads this script at body end — no
// DOMContentLoaded dependency); DOM lookups only `route-indicator`;
// writes via `textContent` only (the injection-safe write); browser
// touches only `tabs.query({active:true,currentWindow:true})`,
// `tabs.onUpdated.addListener`, and `runtime.sendMessage`; exactly one
// `onUpdated` listener. Each event re-asks the live cache and renders
// the ACTIVE tab's own answer — the label is never a remembered one
// (T057 §Analysis finding 7: one code path, and a foreign tab's
// navigation cannot move the active tab's indicator).

'use strict';

(function stargatePopup() {
  // Canonical labels (tasks.md T057; byte-exact — drift against
  // popup.test.js's hard-coded strings fails CI).
  const LABEL_TOR = 'Route: Tor';
  const LABEL_DIRECT = 'Route: Direct (unrouted)';
  const GET_ROUTE = 'stargate:getRoute';

  const indicator = document.getElementById('route-indicator');

  function render(label) {
    indicator.textContent = label;
  }

  // One full ask-and-render for the active tab, always from live
  // state. Every failure inside — an unreachable background page, an
  // empty tabs.query, a malformed reply — degrades to the safe
  // default below; the catch exists so a rejected sendMessage never
  // becomes an unhandled rejection on the popup document (T034b
  // apiReadFailureFailsClosedWithoutThrowing precedent).
  async function refreshActiveLabel() {
    let label = LABEL_DIRECT;
    try {
      const [tab] = await browser.tabs.query({
        active: true,
        currentWindow: true,
      });
      if (tab !== null && typeof tab === 'object' && typeof tab.id === 'number') {
        const answer = await browser.runtime.sendMessage({
          type: GET_ROUTE,
          tabId: tab.id,
        });
        if (
          answer !== null && typeof answer === 'object' &&
          answer.route === 'tor'
        ) {
          label = LABEL_TOR;
        }
      }
    } catch (_err) {
      // Fail closed: label stays the safe default.
    }
    render(label);
  }

  browser.tabs.onUpdated.addListener(function stargatePopupOnTabUpdated() {
    void refreshActiveLabel();
  });

  void refreshActiveLabel();
})();
