// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// T150 / Principles III and V: the background's main-navigation decision
// describes neither whole-tab protection nor successful tunnel establishment.
// The popup queries that authority; it must not infer a route from the tab URL.

'use strict';

(function stargatePopup() {
  const SCOPE = ' Other requests may use different routes. Connection success is not verified.';
  const LABEL_TOR = 'Main navigation decision: Tor' + SCOPE;
  const LABEL_DIRECT = 'Main navigation decision: Direct (unrouted)' + SCOPE;
  const LABEL_BLOCKED = 'Main navigation decision: Blocked by Stargate' + SCOPE;
  const LABEL_UNKNOWN = 'Main navigation decision: Unknown' + SCOPE;
  const GET_ROUTE = 'stargate:getRoute';
  const indicator = document.getElementById('route-indicator');
  let refreshGeneration = 0;

  async function refreshActiveLabel() {
    const generation = ++refreshGeneration;
    // A previous Tor decision cannot stand in for a pending/unreadable answer.
    indicator.textContent = LABEL_UNKNOWN;
    let label = LABEL_UNKNOWN;
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
        if (answer !== null && typeof answer === 'object') {
          if (answer.route === 'tor') label = LABEL_TOR;
          else if (answer.route === 'unrouted') label = LABEL_DIRECT;
          else if (answer.route === 'blocked') label = LABEL_BLOCKED;
        }
      }
    } catch (_err) {
      // An unavailable background gives no evidence of either route.
    }
    if (generation === refreshGeneration) indicator.textContent = label;
  }

  browser.tabs.onUpdated.addListener(function stargatePopupOnTabUpdated() {
    void refreshActiveLabel();
  });

  void refreshActiveLabel();
})();
