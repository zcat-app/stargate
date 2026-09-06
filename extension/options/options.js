// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// options.js — the options page's save flow (T056; FR-019): validate the
// pasted bearer token against the data-model.md §5 shape `^[0-9a-f]{32}$`,
// persist it through StargateStorage.setDeviceToken (which merges into the
// stored device and stamps the hour-bucket save time), and render a
// status line. This page is the EDGE where pasted input becomes the
// stored credential — validation lives here, never in lib/storage.js
// (T052 §Analysis, trust-boundary doctrine).
//
// Fail-closed status mapping (Constitution V honesty): "saved" is
// rendered only after the storage write RESOLVES; a validation failure
// performs zero storage touches (a stored malformed token would poison
// router.js's SOCKS5 password, FR-002); a rejected write renders the
// failure status — never success, never an unhandled rejection on the
// page document.
//
// The canonical storage.local warning is STATIC markup in options.html
// (data-model.md §5.1; the T034e suite gates it byte-exact) — no JS
// involvement, so it is visible whether or not a save ever happens.
//
// Surface (options.save.test.js P1): zero new context globals —
// everything inside this IIFE; the surface is the one submit listener on
// #token-form and the storage.local reach through StargateStorage. No
// storage I/O at eval time; status writes via textContent only.

'use strict';

(function stargateOptions() {
  const TOKEN_PATTERN = /^[0-9a-f]{32}$/;

  // Spec-silent wording, pinned by options.save.test.js (T034c precedent:
  // the suite is the machine side of an unpinned coupling).
  const INVALID_MESSAGE = 'Invalid token: expected 32 hexadecimal characters (0-9, a-f).';
  const SAVED_MESSAGE = 'Token saved.';
  const FAILURE_MESSAGE = 'Could not save the token.';

  const form = document.getElementById('token-form');
  const input = document.getElementById('bearer-token');
  const status = document.getElementById('status');

  form.addEventListener('submit', (event) => {
    // preventDefault: a default form submission would reload the page
    // and discard the status line.
    event.preventDefault();
    void saveToken(input.value);
  });

  async function saveToken(value) {
    if (!TOKEN_PATTERN.test(value)) {
      render(INVALID_MESSAGE);
      return;
    }
    try {
      await StargateStorage.setDeviceToken(value);
      render(SAVED_MESSAGE);
    } catch (_err) {
      render(FAILURE_MESSAGE);
    }
  }

  function render(message) {
    status.textContent = message;
  }
})();
