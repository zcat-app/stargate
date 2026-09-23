// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// router.js — per-request `.onion` routing plus the T136
// authenticated-device/browser-profile/top-level-site isolation tuple.
// Unknown identity remains an unrouted descriptor here; T157 owns browser
// cancellation and packet-level no-fallback proof.

'use strict';

(function stargateRouter() {
  const TOR_HOST = '127.0.0.1';
  const TOR_PORT = 8881;
  const DIRECT = { type: 'direct' };
  const GET_ROUTE = 'stargate:getRoute';
  const PROFILE_KEY = 'isolationProfileId';
  const PROFILE_PATTERN = /^[0-9a-f]{64}$/;
  const textEncoder = new TextEncoder();

  let mirroredToken = null;
  let mirroredKey = null;
  let tokenGeneration = 0;

  const tabDecisions = new Map();
  const documentSites = new Map();
  const tabDocuments = new Map();
  const topDocuments = new Map();
  const MAX_DOCUMENTS_PER_TAB = 64;

  function validTabId(tabId) {
    return typeof tabId === 'number' && Number.isInteger(tabId) && tabId >= 0;
  }

  function validDocumentId(documentId) {
    return typeof documentId === 'string' && documentId !== '';
  }

  function forgetDocument(documentId) {
    const record = documentSites.get(documentId);
    if (!record) return;
    documentSites.delete(documentId);
    const documents = tabDocuments.get(record.tabId);
    if (!documents) return;
    documents.delete(documentId);
    if (documents.size === 0) tabDocuments.delete(record.tabId);
  }

  function forgetTabDocuments(tabId) {
    const documents = tabDocuments.get(tabId);
    if (!documents) return;
    for (const documentId of documents) documentSites.delete(documentId);
    tabDocuments.delete(tabId);
  }

  function bindDocument(tabId, documentId, site) {
    if (!validTabId(tabId) || !validDocumentId(documentId)) {
      throw new Error('missing document identity');
    }
    const existing = documentSites.get(documentId);
    if (existing) {
      if (existing.tabId !== tabId || existing.site !== site) {
        throw new Error('inconsistent document identity');
      }
      return { documentId, record: existing };
    }

    const record = Object.freeze({ tabId, site });
    documentSites.set(documentId, record);
    let documents = tabDocuments.get(tabId);
    if (!documents) {
      documents = new Set();
      tabDocuments.set(tabId, documents);
    }
    documents.add(documentId);
    while (documents.size > MAX_DOCUMENTS_PER_TAB) {
      forgetDocument(documents.values().next().value);
    }
    return { documentId, record };
  }

  function tokenFromDevice(device) {
    return (
      device !== null &&
      typeof device === 'object' &&
      typeof device.bearerToken === 'string' &&
      device.bearerToken !== ''
    ) ? device.bearerToken : null;
  }

  function replaceMirror(device) {
    tokenGeneration += 1;
    mirroredToken = tokenFromDevice(device);
    mirroredKey = null;
    if (mirroredToken === null) return;
    try {
      mirroredKey = crypto.subtle.importKey(
        'raw',
        textEncoder.encode(mirroredToken),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
    } catch {
      return;
    }
    if (mirroredKey !== null) mirroredKey.catch(() => {});
  }

  const tokenReady = (() => {
    const startingGeneration = tokenGeneration;
    return StargateStorage.getDevice()
      .then((device) => {
        if (tokenGeneration === startingGeneration) replaceMirror(device);
      })
      .catch(() => {
        if (tokenGeneration === startingGeneration) replaceMirror(null);
      });
  })();

  function randomProfileId() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
  }

  function loadProfile() {
    return browser.storage.local.get(PROFILE_KEY).then((bag) => {
      if (Object.prototype.hasOwnProperty.call(bag, PROFILE_KEY)) {
        const stored = bag[PROFILE_KEY];
        if (typeof stored !== 'string' || !PROFILE_PATTERN.test(stored)) {
          throw new Error('invalid isolation profile id');
        }
        return stored;
      }
      const created = randomProfileId();
      return browser.storage.local.set({ [PROFILE_KEY]: created }).then(() => created);
    });
  }

  const profileReady = loadProfile();
  profileReady.catch(() => {});

  function requestSite(details) {
    if (details.type === 'main_frame' && details.frameId === 0) {
      return { site: firstPartyDomain(details), document: null };
    }

    if (details.frameId === 0 && typeof details.documentUrl !== 'undefined') {
      if (!validTabId(details.tabId) || !validDocumentId(details.documentId)) {
        throw new Error('missing document identity');
      }
      const currentTop = topDocuments.get(details.tabId);
      if (typeof currentTop !== 'undefined' && currentTop !== details.documentId) {
        throw new Error('retired document identity');
      }
      const site = firstPartyDomain(details);
      return {
        site,
        document: bindDocument(details.tabId, details.documentId, site),
      };
    }

    if (validTabId(details.tabId)) {
      const own = validDocumentId(details.documentId)
        ? documentSites.get(details.documentId)
        : null;
      const parent = validDocumentId(details.parentDocumentId)
        ? documentSites.get(details.parentDocumentId)
        : null;
      if (
        own && parent &&
        (own.tabId !== parent.tabId || own.site !== parent.site)
      ) {
        throw new Error('inconsistent document ancestry');
      }
      const known = own || parent;
      if (known && known.tabId === details.tabId) {
        const document = own
          ? { documentId: details.documentId, record: own }
          : bindDocument(details.tabId, details.documentId, known.site);
        return { site: known.site, document };
      }
    }

    // Invoke the helper so origin-only and missing-context failures keep
    // the same FirstPartyError boundary as malformed document metadata.
    return firstPartyDomain(details);
  }

  function onionDestination(details) {
    try {
      const parsed = new URL(details.url);
      return parsed.hostname.replace(/\.$/, '').toLowerCase().endsWith('.onion');
    } catch {
      return false;
    }
  }

  function requestContext(details) {
    if (typeof details.incognito !== 'boolean') {
      throw new Error('missing private-browsing context');
    }
    if (typeof details.cookieStoreId !== 'string' || details.cookieStoreId === '') {
      throw new Error('missing contextual identity');
    }
    return {
      mode: details.incognito ? 'private' : 'normal',
      cookieStoreId: details.cookieStoreId,
    };
  }

  async function isolationUsername(key, profileId, context, site) {
    const message = JSON.stringify([
      'stargate-isolation-v1',
      profileId,
      context.mode,
      context.cookieStoreId,
      site,
    ]);
    const tag = new Uint8Array(await crypto.subtle.sign(
      'HMAC',
      await key,
      textEncoder.encode(message)
    ));
    return 'sg1:' + Array.from(
      tag,
      (value) => value.toString(16).padStart(2, '0')
    ).join('');
  }

  async function route(details) {
    if (hardeningOk !== true || !onionDestination(details)) {
      return { routed: false };
    }

    await tokenReady;
    const token = mirroredToken;
    const key = mirroredKey;
    const tokenSnapshot = tokenGeneration;
    if (token === null || key === null) return { routed: false };

    try {
      const initiating = requestSite(details);
      const context = requestContext(details);
      const profileId = await profileReady;
      const username = await isolationUsername(
        key, profileId, context, initiating.site
      );
      if (
        tokenSnapshot !== tokenGeneration ||
        token !== mirroredToken ||
        (
          initiating.document !== null &&
          documentSites.get(initiating.document.documentId) !==
            initiating.document.record
        )
      ) {
        return { routed: false };
      }
      return { routed: true, username, token };
    } catch {
      return { routed: false };
    }
  }

  async function routeWithIndicator(details) {
    if (!validTabId(details.tabId) || details.type !== 'main_frame' || details.frameId !== 0) {
      return route(details);
    }
    // T150 / Principles III and V: only main-navigation decisions are displayed.
    // Object identity prevents an old async result reviving a replaced/closed tab.
    const current = { route: undefined };
    tabDecisions.set(details.tabId, current);
    const decision = await route(details);
    if (tabDecisions.get(details.tabId) === current) {
      current.route = decision.routed ? 'tor' : 'unrouted';
    }
    return decision;
  }

  browser.proxy.onRequest.addListener(async function proxyOnRequest(details) {
    const decision = await routeWithIndicator(details);
    if (!decision.routed) return DIRECT;
    return {
      type: 'socks',
      host: TOR_HOST,
      port: TOR_PORT,
      username: decision.username,
      password: decision.token,
      proxyDNS: true,
    };
  });

  browser.webRequest.onBeforeRequest.addListener(
    function stargateOnBeforeRequest(details) {
      if (validTabId(details.tabId)) {
        void routeWithIndicator(details);
      }
      return {};
    },
    { urls: ['<all_urls>'] }
  );

  browser.webNavigation.onCommitted.addListener(
    function stargateDocumentCommitted(details) {
      if (!validTabId(details.tabId) || !validDocumentId(details.documentId)) {
        return;
      }
      if (details.frameId === 0) {
        // Keep the browser's current top-level identity after retiring its
        // site record. Otherwise a late request carrying the old documentId
        // could recreate that retired authority from documentUrl.
        topDocuments.set(details.tabId, details.documentId);
        forgetTabDocuments(details.tabId);
        try {
          const site = firstPartyDomain({
            url: details.url,
            type: 'main_frame',
            frameId: 0,
          });
          bindDocument(details.tabId, details.documentId, site);
        } catch {
          // Opaque or malformed top-level documents remain unbound.
        }
        return;
      }

      if (!validDocumentId(details.parentDocumentId)) return;
      const parent = documentSites.get(details.parentDocumentId);
      if (!parent || parent.tabId !== details.tabId) return;
      try {
        bindDocument(details.tabId, details.documentId, parent.site);
      } catch {
        forgetDocument(details.documentId);
      }
    }
  );

  browser.tabs.onRemoved.addListener(function stargateTabRemoved(tabId) {
    tabDecisions.delete(tabId);
    topDocuments.delete(tabId);
    forgetTabDocuments(tabId);
  });

  browser.runtime.onMessage.addListener(function stargateGetRoute(message) {
    if (message === null || typeof message !== 'object') return undefined;
    if (message.type !== GET_ROUTE) return undefined;
    const tabId = message.tabId;
    if (!validTabId(tabId)) return undefined;
    const decision = tabDecisions.get(tabId)?.route;
    if (decision === 'tor') return Promise.resolve({ route: 'tor' });
    if (decision === 'unrouted') return Promise.resolve({ route: 'unrouted' });
    return Promise.resolve(undefined);
  });

  browser.storage.onChanged.addListener(function stargateOnStorageChanged(
    changes,
    area
  ) {
    if (area !== 'local' || changes === null || typeof changes !== 'object') {
      return;
    }
    if (Object.prototype.hasOwnProperty.call(changes, 'device')) {
      replaceMirror(changes.device.newValue);
    }
  });
})();
