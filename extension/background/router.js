// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
//
// router.js — per-request `.onion` routing plus the T136
// authenticated-device/browser-profile/top-level-site isolation tuple, the
// T157 terminal fail-closed decision shared by proxy/webRequest events and
// the T186 unreachable proxy sink for blocked protected requests.

'use strict';

(function stargateRouter() {
  const TOR_HOST = '127.0.0.1';
  const TOR_PORT = 8881;
  const DIRECT = { type: 'direct' };
  // T186 / FR-004a / Principle III: a blocked protected request must never
  // return `null`. Gecko's ProxyChannelFilter turns `null` into "no proxy": an
  // explicit direct connection that also bypasses the browser/system proxy,
  // and `x.onion.` escapes network.dns.blockDotOnion. A rejected or throwing
  // listener instead selects the default (system) proxy. The blocked result is
  // one SOCKS5h hop over a Unix socket whose path cannot exist — `/dev/null`
  // is not a directory, so no unprivileged process can create or listen on it
  // (a host-root attacker already owns the loopback ports and this extension
  // and is outside this protection's threat class) — then the terminal `null`,
  // so no failover remains. proxyDNS keeps the name from being resolved
  // locally; the hop carries no credential or identity. Unlike a loopback TCP
  // port, no local user can bind the sink while Stargate is down. Live
  // evidence (Mullvad Browser 140/153 ESR): THREAT-MODEL T186.
  const BLOCKED_SINK_HOST = 'file:///dev/null/stargate-blocked';
  const GET_ROUTE = 'stargate:getRoute';
  const PROFILE_KEY = 'isolationProfileId';
  const PROFILE_PATTERN = /^[0-9a-f]{64}$/;
  const TOKEN_PATTERN = /^[0-9a-f]{32}$/;
  const MAX_REQUEST_DECISIONS = 512;
  const textEncoder = new TextEncoder();

  let mirroredToken = null;
  let mirroredKey = null;
  let tokenGeneration = 0;

  const tabDecisions = new Map();
  const requestDecisions = new Map();
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
      TOKEN_PATTERN.test(device.bearerToken)
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

  function blockedProxy() {
    // A fresh object per call: Firefox validates and rewrites the fields.
    // The port is required by ProxyInfoData validation and unused for Unix
    // sockets.
    const sink = {
      type: 'socks',
      host: BLOCKED_SINK_HOST,
      port: 1,
      proxyDNS: true,
    };
    return [sink, null];
  }

  function onionDestination(details) {
    try {
      const parsed = new URL(details.url);
      // Every trailing-dot and case variant is the same protected
      // destination (T186); classify toward protection.
      return parsed.hostname.replace(/\.+$/, '').toLowerCase().endsWith('.onion');
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
    if (!onionDestination(details)) return { route: 'direct' };
    if (hardeningOk !== true) return { route: 'blocked' };

    await tokenReady;
    const token = mirroredToken;
    const key = mirroredKey;
    const tokenSnapshot = tokenGeneration;
    if (token === null || key === null) return { route: 'blocked' };

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
        return { route: 'blocked' };
      }
      return {
        route: 'tor',
        username,
        token,
        tokenGeneration: tokenSnapshot,
        document: initiating.document,
      };
    } catch {
      return { route: 'blocked' };
    }
  }

  function requestId(details) {
    return typeof details.requestId === 'string' && details.requestId !== ''
      ? details.requestId
      : null;
  }

  // Only fields present at both Firefox decision points and relevant to the
  // route are compared. proxyInfo is deliberately excluded: it is the result
  // being verified by onBeforeRequest, not an input to the decision.
  function requestFingerprint(details) {
    return JSON.stringify([
      details.url ?? null,
      details.method ?? null,
      details.type ?? null,
      details.tabId ?? null,
      details.frameId ?? null,
      details.parentFrameId ?? null,
      details.incognito ?? null,
      details.cookieStoreId ?? null,
      details.documentId ?? null,
      details.parentDocumentId ?? null,
      details.documentUrl ?? null,
      details.originUrl ?? null,
    ]);
  }

  function beginIndicator(details, fingerprint) {
    if (
      !validTabId(details.tabId) ||
      details.type !== 'main_frame' ||
      details.frameId !== 0
    ) {
      return null;
    }
    // T150 / Principles III and V: only main-navigation decisions are displayed.
    // Object identity prevents an old async result reviving a replaced/closed tab.
    const current = { route: undefined, fingerprint };
    tabDecisions.set(details.tabId, current);
    return current;
  }

  function commitIndicator(details, indicator, routeName) {
    if (
      indicator !== null &&
      tabDecisions.get(details.tabId) === indicator &&
      indicator.fingerprint === requestFingerprint(details)
    ) {
      indicator.route = routeName;
    }
  }

  function rememberRequest(details) {
    const id = requestId(details);
    const fingerprint = requestFingerprint(details);
    const indicator = beginIndicator(details, fingerprint);
    if (id === null) return { id, fingerprint, indicator, decision: null };

    // The catch is part of the privacy boundary: Firefox treats a rejected
    // proxy listener as "use the default proxy configuration". A protected
    // internal failure must instead become an explicit blocked decision.
    const record = {
      id,
      tabId: details.tabId,
      fingerprint,
      indicator,
      decision: Promise.resolve()
        .then(() => route(details))
        .catch(() => ({ route: 'blocked' })),
    };
    requestDecisions.set(id, record);
    while (requestDecisions.size > MAX_REQUEST_DECISIONS) {
      requestDecisions.delete(requestDecisions.keys().next().value);
    }
    return record;
  }

  function expectedTorProxy(proxyInfo) {
    return (
      proxyInfo !== null &&
      typeof proxyInfo === 'object' &&
      proxyInfo.type === 'socks' &&
      proxyInfo.host === TOR_HOST &&
      proxyInfo.port === TOR_PORT &&
      proxyInfo.proxyDNS === true
    );
  }

  function decisionStillCurrent(decision) {
    return (
      hardeningOk === true &&
      decision.route === 'tor' &&
      decision.tokenGeneration === tokenGeneration &&
      decision.token === mirroredToken &&
      (
        decision.document === null ||
        documentSites.get(decision.document.documentId) ===
          decision.document.record
      )
    );
  }

  browser.proxy.onRequest.addListener(function proxyOnRequest(details) {
    // onionDestination never throws; everything after it is guarded so a
    // listener failure cannot reach Firefox's default-proxy path.
    const protectedDestination = onionDestination(details);
    const failed = () => (protectedDestination ? blockedProxy() : DIRECT);
    try {
      const record = rememberRequest(details);
      if (record.id === null) return Promise.resolve(failed());
      return record.decision.then((decision) => {
        if (decision.route === 'direct') return DIRECT;
        if (decision.route !== 'tor') return blockedProxy();
        return [{
          type: 'socks',
          host: TOR_HOST,
          port: TOR_PORT,
          username: decision.username,
          password: decision.token,
          proxyDNS: true,
        }, null];
      }).catch(failed);
    } catch {
      return Promise.resolve(failed());
    }
  }, { urls: ['<all_urls>'] });

  browser.webRequest.onBeforeRequest.addListener(
    async function stargateOnBeforeRequest(details) {
      const protectedDestination = onionDestination(details);
      const id = requestId(details);
      const record = id === null ? null : requestDecisions.get(id);
      if (
        record === null ||
        typeof record === 'undefined' ||
        record.fingerprint !== requestFingerprint(details)
      ) {
        if (id !== null) requestDecisions.delete(id);
        if (protectedDestination) {
          const current = validTabId(details.tabId)
            ? tabDecisions.get(details.tabId)
            : null;
          commitIndicator(details, current ?? null, 'blocked');
          return { cancel: true };
        }
        return {};
      }
      requestDecisions.delete(id);
      const decision = await record.decision;
      if (decision.route === 'direct' && !protectedDestination) {
        commitIndicator(details, record.indicator, 'direct');
        return {};
      }
      if (
        protectedDestination &&
        decisionStillCurrent(decision) &&
        expectedTorProxy(details.proxyInfo)
      ) {
        commitIndicator(details, record.indicator, 'tor');
        return {};
      }
      commitIndicator(details, record.indicator, 'blocked');
      return { cancel: true };
    },
    { urls: ['<all_urls>'] },
    ['blocking']
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
    for (const [id, record] of requestDecisions) {
      if (record.tabId === tabId) requestDecisions.delete(id);
    }
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
    if (decision === 'direct') return Promise.resolve({ route: 'unrouted' });
    if (decision === 'blocked') return Promise.resolve({ route: 'blocked' });
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
