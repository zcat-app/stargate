// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// storage.js — thin async wrappers over `browser.storage.local.get/set`
// for the device schema (data-model.md §5): `device.{name, bearerToken,
// tokenStoredAt}`. Consumers: background/router.js (T054) reads the token
// for the SOCKS5 password inside `proxy.onRequest`; options/options.js
// (T056) writes the validated one.
//
// Deliberately NOT here, per the trust-boundary doctrine (internal
// callers are trusted; validation lives at edges): token-format
// validation — data-model.md §5 puts `^[0-9a-f]{32}$` "in the options
// page" — and any non-device storage.local field (arch §14.4; T055's
// hardening record owns its own key). The wrapper carries no shape
// policy: setDevice stores what it is given, verbatim.
//
// Surface (T034g — MV2 lib scripts share one background-page global
// scope): exactly one new global, `StargateStorage`, declared with `var`
// so it is a true global property; the methods are object-literal async
// methods so no top-level function declarations leak into the shared
// scope. No I/O at eval time — the non-persistent background page must
// not do work at script load.

'use strict';

var StargateStorage = {
  // Resolves the stored device value verbatim, or undefined when absent —
  // never a fabricated default: router.js/options.js must see genuine
  // unconfigured state, not an impersonated one.
  async getDevice() {
    const bag = await browser.storage.local.get('device');
    return bag.device;
  },

  // Stores the device object verbatim under the single data-model.md §5
  // key.
  async setDevice(device) {
    await browser.storage.local.set({ device });
  },

  // Merges the token + save-time stamp into the stored device, preserving
  // sibling fields (notably `name`). The hour-bucket granularity is
  // spec-pinned (`<hourBucket>`); the formula is this ticket's decision:
  // floor(epoch ms / 3600000) — UTC-immune, since epoch time has no
  // timezone (T052 §Analysis residue note).
  async setDeviceToken(bearerToken) {
    const current = await this.getDevice();
    await this.setDevice({
      ...(current || {}),
      bearerToken,
      tokenStoredAt: Math.floor(Date.now() / 3600000),
    });
  },
};
