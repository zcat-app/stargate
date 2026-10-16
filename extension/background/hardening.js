// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// T205 / Constitution III: a current runtime gate is volatile, never an
// event/hour/error record. Firefox exposes only the WebRTC setting here;
// DoH/DoT/HTTP-3 remain external profile preconditions (arch §14.5).
// Shared MV2 scope retains only hardeningOk and auditHardening. The finite
// auditHardening.status is unknown until cleanup and the latest measurement
// complete; enabled/disabled describe only that completed check, not ongoing
// surveillance or whole-profile verification. T190 owns audit cadence.

'use strict';

var hardeningOk = false;

var auditHardening = (function stargateHardening() {
  let currentInvocation;

  async function removeLegacy() {
    try {
      // Delete the obsolete key without reading its shape or touching client
      // credentials/configuration. No durable migration marker (Principle III).
      await browser.storage.local.remove('hardening');
      return true;
    } catch {
      return false;
    }
  }

  async function measure() {
    try {
      const setting = await browser.privacy.network.peerConnectionEnabled.get({});
      const value = setting !== null && typeof setting === 'object' ? setting.value : setting;
      return value === false ? 'disabled' : value === true ? 'enabled' : 'unknown';
    } catch {
      return 'unknown';
    }
  }

  async function audit() {
    const invocation = {};
    currentInvocation = invocation;
    hardeningOk = false;
    audit.status = 'unknown';
    const [removed, status] = await Promise.all([removeLegacy(), measure()]);
    // A delayed older success must never reopen a newer failed gate (FR-004a).
    if (currentInvocation !== invocation) return hardeningOk;
    audit.status = removed ? status : 'unknown';
    hardeningOk = audit.status === 'disabled';
    if (hardeningOk) return true;
    try {
      const notificationMessage = !removed
        ? 'Stargate could not complete its runtime hardening initialization, so all non-Direct routes remain blocked. Restart the browser to retry. WebRTC is the only hardening surface this extension can verify at runtime; this notification does not verify the rest of the browser profile.'
        : (audit.status === 'enabled'
          ? 'WebRTC is enabled, so Stargate has blocked all non-Direct routes. ' +
            'To restore them, set media.peerconnection.enabled to false in ' +
            'about:config and restart the browser. '
          : 'Stargate could not verify WebRTC is disabled, so all non-Direct ' +
            'routes remain blocked. To restore them, confirm ' +
            'media.peerconnection.enabled is false in about:config and restart ' +
            'the browser. ') + 'WebRTC is the ' +
            'only hardening surface this extension can verify at runtime. ' +
            'DoH, DoT and HTTP/3 require separate browser-profile checks; ' +
            'this notification does not verify them.';
      await browser.notifications.create({
        type: 'basic',
        title: 'Stargate: non-Direct routing blocked',
        message: notificationMessage,
      });
    } catch {
      // Notification delivery is explanatory only, never authorization or a
      // raw-error diagnostic/history sink (Constitution III).
    }
    return hardeningOk;
  }

  audit.status = 'unknown';
  return audit;
})();

// The persistent MV2 background page measures on startup/process restart.
// Both external API paths and notification rejection are contained above.
auditHardening();
