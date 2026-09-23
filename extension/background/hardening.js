// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// hardening.js — the extension's runtime hardening gate: non-Direct
// routing is fail-closed against WebRTC (FR-004(b) as amended by T091;
// arch §14.5 Part 2; THREAT-MODEL §5.3).
//
// Enforcement boundary (T091; Constitution III bullet 3): the ONLY
// hardening surface Firefox's stable WebExtensions API truthfully
// exposes is `browser.privacy.network.peerConnectionEnabled`. The DoH /
// DoT / HTTP-3 preferences are not extension-readable — they are
// release-cadence-verified out-of-band
// (tests/live-e2e/mullvad-browser-hardening/, arch §14.5 Part 1), so
// this gate neither reads nor names them: a dialog or audit record that
// claimed a runtime block on those surfaces would be the false
// assurance T091 removed (Constitution V; pinned as a negative-token
// gate by T034b's failureDialogNeverClaimsDohDotHttp3RuntimeBlocks).
//
// Surface (T034b §Analysis "Pinned surface" — the authorization
// boundary this module conforms to): exactly two new globals on the
// shared MV2 background-page scope (firstparty.js / storage.js /
// router.js all load here; every extra top-level binding is a
// namespace-collision surface, T034g):
//   - `hardeningOk` — boolean; `false` until the first audit
//     completes, then a pure function of the `peerConnectionEnabled`
//     value: `true` iff the value read is exactly `false`. router.js
//     (T054) checks this before returning a SOCKS descriptor for
//     non-Direct routes (FR-004); Direct routes are unaffected.
//   - `auditHardening()` — async; re-reads the setting every call
//     (never serves a cached flag), updates `hardeningOk`, and on
//     failure fires the blocking notification plus the
//     `storage.local.hardening.lastAuditResult` operator record
//     (arch §14.5 failure UX items 1 and 3). Success is silent and
//     write-free. Resolves only after its side effects are observable.
//     Never throws synchronously and never rejects: an unreachable or
//     misbehaving API degrades to fail-closed (FR-004), never to an
//     unhandled rejection on the background page.
//
// Script evaluation IS the browser-startup/restart moment (arch §14.5
// Part 2 "read at startup and on browser restart" — the non-persistent
// background page re-evaluates its scripts on every start), so the
// audit runs once at load, below.

'use strict';

var hardeningOk = false;

var auditHardening = async function auditHardening() {
  // Read the one real surface. Firefox `privacy.*` Settings resolve
  // `{ value, levelOfControl }`; the value under test is `.value`. The
  // raw-value form (what the T034b mock resolves) is accepted too, so
  // the extraction is normalized at the API edge rather than assuming
  // one shape. `levelOfControl` is deliberately ignored: arch §14.5
  // pins the gate to the VALUE only.
  let readValue;
  let readError = null;
  try {
    const setting = await browser.privacy.network.peerConnectionEnabled.get({});
    readValue = setting !== null && typeof setting === 'object'
      ? setting.value
      : setting;
  } catch (err) {
    readError = err && err.message ? err.message : String(err);
  }

  // The flag is a pure function of the read (arch §14.5 failure UX
  // item 2): only the exactly-`false` (hardened) state opens non-Direct
  // routing; enabled, reachable-but-unset, or unreadable all fail
  // closed (FR-004).
  hardeningOk = readError === null && readValue === false;
  if (hardeningOk) {
    return hardeningOk;
  }

  // Failure UX item 1 (arch §14.5): a blocking dialog naming WebRTC and
  // the pref remediation. It states — without naming them — that the
  // remaining hardening surfaces are verified outside the extension at
  // release cadence; naming them is neither needed nor safe, since the
  // only runtime-true sentence about them is the one this copy makes.
  try {
    const notificationMessage = readError === null && readValue === true
      ? 'WebRTC is enabled, so Stargate has blocked all non-Direct routes. ' +
        'To restore them, set media.peerconnection.enabled to false in ' +
        'about:config and restart the browser. '
      : 'Stargate could not verify WebRTC is disabled, so all non-Direct ' +
        'routes remain blocked. To restore them, confirm ' +
        'media.peerconnection.enabled is false in about:config and restart ' +
        'the browser. ';
    await browser.notifications.create({
      type: 'basic',
      title: 'Stargate: non-Direct routing blocked',
      message:
        notificationMessage + 'WebRTC is the ' +
        'only hardening surface this extension can verify at runtime; ' +
        'the rest of the hardened profile is verified outside the ' +
        'extension at each Stargate release.',
      requireInteraction: true,
    });
  } catch (err) {
    console.warn('stargate: hardening notification failed:', err);
  }

  // Failure UX item 3 (arch §14.5): the operator-facing failure record
  // at storage.local.hardening (arch §14.4 layout; the admin-dashboard
  // consumer is a future signed-export flow). Success writes nothing.
  // lastAuditedAt reuses the spec-pinned hour-bucket granularity and
  // formula (arch §14.4 `<hourBucket>`; T052: floor(epoch ms/3600000)).
  try {
    await browser.storage.local.set({
      hardening: {
        lastAuditedAt: Math.floor(Date.now() / 3600000),
        lastAuditResult: {
          blockedSurface: 'webrtc',
          pref: 'privacy.network.peerConnectionEnabled',
          readError,
        },
      },
    });
  } catch (err) {
    console.warn('stargate: hardening audit record failed:', err);
  }

  return hardeningOk;
};

// Startup audit (arch §14.5 Part 2). The returned promise is
// deliberately not awaited: auditHardening contains its own failures,
// so the floating promise cannot become an unhandled rejection.
auditHardening();
