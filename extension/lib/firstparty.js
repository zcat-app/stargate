// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// firstparty.js — initiating-top-level-site canonicalization for
// the browser SOCKS isolation tuple (FR-002; foundation-boundaries.md
// “Browser SOCKS isolation identity — T136”). Router.js owns browser API
// state and turns this type-tagged site into the opaque wire username.

'use strict';

// Firefox 153's native publicSuffix API is the suffix authority. It uses
// the browser's shipped ICANN and PRIVATE data without extension network I/O.
var firstPartyDomain = (() => {
  function sentinel(kind, value) {
    const err = new Error(
      'firstPartyDomain: unavailable ' + kind +
        ' (typeof ' + typeof value +
        ') — refusing a guessed isolation site (FR-002/T136)'
    );
    err.name = 'FirstPartyError';
    return err;
  }

  function registrableDomain(host) {
    let domain;
    try {
      domain = browser.publicSuffix.getDomain(host);
    } catch {
      throw sentinel('registrable DNS site', host);
    }
    if (typeof domain !== 'string' || domain === '') {
      throw sentinel('registrable DNS site', host);
    }
    return domain.toLowerCase();
  }

  function typedSite(governing, kind) {
    if (typeof governing !== 'string') throw sentinel(kind, governing);

    let parsed;
    try {
      parsed = new URL(governing);
    } catch {
      throw sentinel(kind, governing);
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw sentinel(kind, governing);
    }

    const host = parsed.hostname.replace(/\.$/, '').toLowerCase();
    if (host === '' || host.split('.').some((label) => label === '')) {
      throw sentinel(kind, governing);
    }
    if (host.endsWith('.onion')) return 'onion:' + host;
    if (host.startsWith('[') && host.endsWith(']')) return 'ipv6:' + host;
    if (
      host.split('.').length === 4 &&
      host.split('.').every(
        (label) => /^\d+$/.test(label) && Number(label) <= 255
      )
    ) {
      return 'ipv4:' + host;
    }
    return 'dns:' + registrableDomain(host);
  }

  return function firstPartyDomainForRequest(requestDetails) {
    if (
      requestDetails &&
      requestDetails.type === 'main_frame' &&
      requestDetails.frameId === 0
    ) {
      return typedSite(requestDetails.url, 'top-level navigation URL');
    }

    if (
      requestDetails &&
      requestDetails.frameId === 0 &&
      typeof requestDetails.documentUrl !== 'undefined'
    ) {
      return typedSite(requestDetails.documentUrl, 'documentUrl');
    }

    // Firefox's originUrl can identify an intermediate stylesheet, not
    // the initiating top-level document. It remains lower precedence but
    // cannot independently authorize a protected route (MDN RequestDetails;
    // Constitution III). A committed top-level site is supplied directly
    // by router.js for nested/worker contexts instead of entering here.
    if (requestDetails && typeof requestDetails.originUrl !== 'undefined') {
      throw sentinel('untrusted originUrl', requestDetails.originUrl);
    }
    throw sentinel('initiating top-level context', undefined);
  };
})();
