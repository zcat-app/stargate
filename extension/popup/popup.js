// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// T150 / Principles III and V: the background's main-navigation decision
// describes neither whole-tab protection nor successful tunnel establishment.
// The popup queries that authority; it must not infer a route from the tab URL.
// T188: the background also reports two protection preconditions the popup
// states before any route: private-window access and the profile's
// fail-closed proxy baseline.

'use strict';

(function stargatePopup() {
  const SCOPE = ' Other requests may use different routes. Connection success is not verified.';
  const LABEL_TOR = 'Main navigation decision: Tor' + SCOPE;
  const LABEL_DIRECT = 'Main navigation decision: Direct (unrouted)' + SCOPE;
  const LABEL_BLOCKED = 'Main navigation decision: Blocked by Stargate' + SCOPE;
  const LABEL_UNKNOWN = 'Main navigation decision: Unknown' + SCOPE;
  const LABEL_NO_PRIVATE_ACCESS =
    'Stargate is not protecting private windows: "Run in Private Windows" is not ' +
    'allowed or not confirmed. Stargate blocks the .onion requests it can see. ' +
    'Allow it in about:addons > Stargate.';
  const BASELINE_WARNING =
    'Warning: the Stargate fail-closed proxy baseline of this profile is missing, ' +
    'changed or unverifiable, so requests Stargate does not route follow the browser ' +
    'proxy settings. Reinstall browser-profile/user.js (quickstart).';
  const HARDENING_DISABLED = 'Runtime hardening: WebRTC disabled at last check.';
  const HARDENING_ENABLED = 'Runtime hardening: WebRTC enabled at last check; non-Direct routing blocked.';
  const HARDENING_UNKNOWN = 'Runtime hardening: Unknown; non-Direct routing readiness is not confirmed.';
  const hardeningIndicator = document.getElementById('hardening-status');
  const GET_ROUTE = 'stargate:getRoute';
  const indicator = document.getElementById('route-indicator');
  let refreshGeneration = 0;

  async function refreshActiveLabel() {
    const generation = ++refreshGeneration;
    // A previous Tor decision cannot stand in for a pending/unreadable answer.
    indicator.textContent = LABEL_UNKNOWN;
    hardeningIndicator.textContent = HARDENING_UNKNOWN;
    let label = LABEL_UNKNOWN;
    let warning = false;
    let hardeningLabel = HARDENING_UNKNOWN;
    try {
      const [tab] = await browser.tabs.query({
        active: true,
        currentWindow: true,
      });
      if (tab !== null && typeof tab === 'object' && typeof tab.id === 'number') {
        const answer = await browser.runtime.sendMessage({
          type: GET_ROUTE,
          tabId: tab.id,
          includeHardening: true,
        });
        if (answer !== null && typeof answer === 'object') {
          if (answer.hardening === 'disabled') hardeningLabel = HARDENING_DISABLED;
          else if (answer.hardening === 'enabled') hardeningLabel = HARDENING_ENABLED;
          if (answer.route === 'tor') label = LABEL_TOR;
          else if (answer.route === 'unrouted') label = LABEL_DIRECT;
          else if (answer.route === 'blocked') label = LABEL_BLOCKED;
          else if (answer.route === 'no-private-access') label = LABEL_NO_PRIVATE_ACCESS;
          // Only an explicit, recognised intact state suppresses the warning.
          warning = Object.prototype.hasOwnProperty.call(answer, 'baseline');
        }
      }
    } catch (_err) {
      // An unavailable background gives no evidence of either route.
    }
    if (generation === refreshGeneration) {
      hardeningIndicator.textContent = hardeningLabel;
      indicator.textContent = warning ? BASELINE_WARNING + ' ' + label : label;
    }
  }

  browser.tabs.onUpdated.addListener(function stargatePopupOnTabUpdated() {
    void refreshActiveLabel();
  });

  void refreshActiveLabel();
})();
