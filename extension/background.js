/**
 * Background service worker v2.3
 * - Auto-analyzes every navigation, updates badge
 * - Warning banner for caution domains
 * - Context menu opens a popup window with full analysis
 */

const WORKER_URL = 'https://domain-authenticator.keertipc7.workers.dev';

const BADGE_COLORS = {
  trusted: '#10b981', likely_safe: '#3b82f6', caution: '#f59e0b',
  suspicious: '#f97316', dangerous: '#ef4444',
};

const SKIP_PROTOCOLS = ['chrome:', 'chrome-extension:', 'about:', 'edge:', 'brave:', 'file:', 'devtools:'];

// ─── In-memory cache ──────────────────────────────────────────────────────────

const analysisCache = new Map();
const MEMORY_CACHE_TTL = 5 * 60 * 1000;

function getCached(domain) {
  const entry = analysisCache.get(domain);
  if (entry && Date.now() - entry.time < MEMORY_CACHE_TTL) return entry.data;
  analysisCache.delete(domain);
  return null;
}

function setCache(domain, data) {
  analysisCache.set(domain, { data, time: Date.now() });
  if (analysisCache.size > 500) analysisCache.delete(analysisCache.keys().next().value);
}

function clearCache(domain) {
  analysisCache.delete(domain);
}

// ─── API call ─────────────────────────────────────────────────────────────────

async function analyzeDomain(domain, force = false) {
  if (!force) {
    const cached = getCached(domain);
    if (cached) return cached;
  }
  try {
    const resp = await fetch(`${WORKER_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, force }),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    setCache(domain, data);
    return data;
  } catch (e) {
    console.error('analyzeDomain error:', e);
    return null;
  }
}

// ─── Badge ────────────────────────────────────────────────────────────────────

function updateBadge(tabId, result) {
  if (!result) {
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#6b7280' });
    return;
  }
  chrome.action.setBadgeText({ tabId, text: String(result.trustScore) });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[result.verdict] || '#6b7280' });
}

// ─── Navigation ───────────────────────────────────────────────────────────────

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  try {
    const url = new URL(details.url);
    if (SKIP_PROTOCOLS.some(p => url.protocol.startsWith(p))) return;

    const domain = url.hostname.replace(/^www\./, '');
    const overrides = await chrome.storage.local.get('user_overrides');
    const userOverrides = overrides.user_overrides || {};

    if (userOverrides[domain] === 'safe') {
      updateBadge(details.tabId, { trustScore: 95, verdict: 'trusted' });
      return;
    }

    chrome.action.setBadgeText({ tabId: details.tabId, text: '...' });
    chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: '#6b7280' });

    const result = await analyzeDomain(domain);
    if (!result) return;

    updateBadge(details.tabId, result);

    await chrome.storage.session.set({
      [`result:${details.tabId}`]: result,
      [`domain:${domain}`]: result,
    });

    if (result.verdict === 'caution') {
      try { chrome.tabs.sendMessage(details.tabId, { type: 'WARN_BANNER', data: result }); } catch {}
    }
  } catch (e) {
    console.error('onCompleted error:', e);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab?.url) return;
    const url = new URL(tab.url);
    if (SKIP_PROTOCOLS.some(p => url.protocol.startsWith(p))) return;
    const domain = url.hostname.replace(/^www\./, '');
    const cached = getCached(domain);
    if (cached) {
      updateBadge(tabId, cached);
      await chrome.storage.session.set({
        [`result:${tabId}`]: cached,
        [`domain:${domain}`]: cached,
      });
    }
  } catch {}
});

// ─── Context menu ──────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'analyze-link', title: 'Analyze link safety', contexts: ['link'] });
  chrome.contextMenus.create({ id: 'analyze-page', title: 'Analyze this page', contexts: ['page'] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let domain;
  if (info.menuItemId === 'analyze-link' && info.linkUrl) {
    try { domain = new URL(info.linkUrl).hostname.replace(/^www\./, ''); } catch {}
  } else if (info.menuItemId === 'analyze-page' && tab?.url) {
    try { domain = new URL(tab.url).hostname.replace(/^www\./, ''); } catch {}
  }
  if (!domain) return;

  // Pre-fetch analysis and store it
  const result = await analyzeDomain(domain);
  if (result) {
    await chrome.storage.session.set({
      [`domain:${domain}`]: result,
      'contextAnalysis': result,
    });
  }

  // Open a small popup window with the full analysis
  chrome.windows.create({
    url: chrome.runtime.getURL('popup/popup.html') + '?context=1&domain=' + encodeURIComponent(domain),
    type: 'popup',
    width: 400,
    height: 580,
  });
});

// ─── Message handler ───────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === 'GET_ANALYSIS') {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) { sendResponse({ error: 'No active tab found' }); return; }

        let url;
        try { url = new URL(tab.url); } catch {
          sendResponse({ error: 'Could not parse tab URL' }); return;
        }

        if (SKIP_PROTOCOLS.some(p => url.protocol.startsWith(p))) {
          sendResponse({ error: 'Not a web page — navigate to a website first' }); return;
        }

        const domain = url.hostname.replace(/^www\./, '');

        // Step 1: in-memory cache
        const memCached = getCached(domain);
        if (memCached) { sendResponse(memCached); return; }

        // Step 2: session storage by tab ID
        try {
          const byTab = await chrome.storage.session.get(`result:${tab.id}`);
          if (byTab[`result:${tab.id}`]) {
            const result = byTab[`result:${tab.id}`];
            setCache(domain, result);
            sendResponse(result); return;
          }
        } catch {}

        // Step 3: session storage by domain
        try {
          const byDomain = await chrome.storage.session.get(`domain:${domain}`);
          if (byDomain[`domain:${domain}`]) {
            const result = byDomain[`domain:${domain}`];
            setCache(domain, result);
            sendResponse(result); return;
          }
        } catch {}

        // Step 4: fetch fresh
        const result = await analyzeDomain(domain);
        if (result) {
          await chrome.storage.session.set({
            [`result:${tab.id}`]: result,
            [`domain:${domain}`]: result,
          });
          sendResponse(result);
        } else {
          sendResponse({ error: `Could not analyze ${domain} — check your Worker URL` });
        }
      } catch (e) {
        console.error('GET_ANALYSIS error:', e);
        sendResponse({ error: e.message || 'Unknown error' });
      }
    })();
    return true;
  }

  if (msg.type === 'GET_FRESH_ANALYSIS') {
    (async () => {
      try {
        const result = await analyzeDomain(msg.domain, true);
        if (result) {
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tab) {
            await chrome.storage.session.set({
              [`result:${tab.id}`]: result,
              [`domain:${msg.domain}`]: result,
            });
          }
          sendResponse(result);
        } else {
          sendResponse({ error: 'Refresh failed' });
        }
      } catch (e) { sendResponse({ error: e.message }); }
    })();
    return true;
  }

  if (msg.type === 'OVERRIDE_DOMAIN') {
    (async () => {
      const stored = await chrome.storage.local.get('user_overrides');
      const all = stored.user_overrides || {};
      all[msg.domain] = msg.tag;
      await chrome.storage.local.set({ user_overrides: all });
      clearCache(msg.domain);
      sendResponse({ success: true });
    })();
    return true;
  }

  if (msg.type === 'SUBMIT_VOTE') {
    (async () => {
      try {
        const stored = await chrome.storage.local.get('userId');
        const userId = stored.userId || 'user_' + Math.random().toString(36).slice(2, 10);
        if (!stored.userId) await chrome.storage.local.set({ userId });

        const resp = await fetch(`${WORKER_URL}/vote`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: msg.domain, vote: msg.vote, userId }),
        });
        const data = await resp.json();

        clearCache(msg.domain);
        try {
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tab) await chrome.storage.session.remove([`result:${tab.id}`, `domain:${msg.domain}`]);
        } catch {}

        sendResponse(data);
      } catch (e) { sendResponse({ error: e.message }); }
    })();
    return true;
  }

  if (msg.type === 'REPORT_MISTAKE') {
    (async () => {
      try {
        const resp = await fetch(`${WORKER_URL}/report`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(msg.data),
        });
        sendResponse(await resp.json());
      } catch (e) { sendResponse({ error: e.message }); }
    })();
    return true;
  }
});