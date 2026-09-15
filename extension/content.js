/**
 * Content script — injects block overlays and warning banners
 */

let bannerInjected = false;
let blockInjected = false;

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'BLOCK_PAGE' && !blockInjected) {
    blockInjected = true;
    showBlockOverlay(msg.data);
  }
  if (msg.type === 'WARN_BANNER' && !bannerInjected) {
    bannerInjected = true;
    showWarningBanner(msg.data);
  }
  if (msg.type === 'CONTEXT_RESULT') {
    showContextToast(msg.data);
  }
});

function showBlockOverlay(data) {
  const overlay = document.createElement('div');
  overlay.id = 'da-block-overlay';
  overlay.innerHTML = `
    <div class="da-block-card">
      <div class="da-block-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" width="48" height="48">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/>
        </svg>
      </div>
      <h1 class="da-block-title">Site blocked by Domain Authenticator</h1>
      <p class="da-block-domain">${data.domain}</p>
      <div class="da-block-score">
        <span class="da-score-num">${data.trustScore}</span>
        <span class="da-score-label">trust score</span>
      </div>
      <p class="da-block-reason">${data.ai?.summary || 'This domain has been flagged as potentially dangerous.'}</p>
      ${data.ai?.technical_detail ? `<p class="da-block-technical">${data.ai.technical_detail}</p>` : ''}
      ${data.ai?.flags?.length ? `<div class="da-block-flags">${data.ai.flags.map(f => `<span class="da-flag">${f}</span>`).join('')}</div>` : ''}
      <div class="da-block-actions">
        <button class="da-btn da-btn-back" id="da-go-back">Go back to safety</button>
        <button class="da-btn da-btn-proceed" id="da-proceed">I understand the risks — proceed anyway</button>
      </div>
      <p class="da-block-powered">Powered by Cloudflare Workers AI</p>
    </div>
  `;
  document.documentElement.appendChild(overlay);

  document.getElementById('da-go-back').addEventListener('click', () => {
    history.back();
  });

  document.getElementById('da-proceed').addEventListener('click', () => {
    overlay.remove();
    blockInjected = false;
    // Mark as user-override for this session
    chrome.runtime.sendMessage({ type: 'OVERRIDE_DOMAIN', domain: data.domain, tag: 'safe' });
  });
}

function showWarningBanner(data) {
  const banner = document.createElement('div');
  banner.id = 'da-warn-banner';
  banner.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18" style="flex-shrink:0">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
    <span><strong>${data.domain}</strong> — ${data.ai?.summary || 'This site has some risk signals. Proceed with caution.'}</span>
    <span class="da-banner-score">Trust: ${data.trustScore}/100</span>
    <button id="da-dismiss-banner" class="da-banner-close">&times;</button>
  `;
  document.documentElement.appendChild(banner);

  document.getElementById('da-dismiss-banner').addEventListener('click', () => {
    banner.remove();
    bannerInjected = false;
  });

  // Auto-dismiss after 10s
  setTimeout(() => {
    if (banner.parentNode) {
      banner.style.opacity = '0';
      setTimeout(() => { banner.remove(); bannerInjected = false; }, 300);
    }
  }, 10000);
}

function showContextToast(data) {
  // Remove existing toast
  const existing = document.getElementById('da-context-toast');
  if (existing) existing.remove();

  const colors = { trusted: '#10b981', likely_safe: '#3b82f6', caution: '#f59e0b', suspicious: '#f97316', dangerous: '#ef4444' };
  const labels = { trusted: 'Trusted', likely_safe: 'Likely safe', caution: 'Caution', suspicious: 'Suspicious', dangerous: 'Dangerous' };

  const toast = document.createElement('div');
  toast.id = 'da-context-toast';
  toast.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px">
      <div style="width:36px;height:36px;border-radius:50%;background:${colors[data.verdict]};display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:13px">${data.trustScore}</div>
      <div>
        <div style="font-weight:600;font-size:13px;color:#e6edf3">${data.domain}</div>
        <div style="font-size:12px;color:${colors[data.verdict]}">${labels[data.verdict] || data.verdict}</div>
      </div>
    </div>
    <div style="font-size:12px;color:#8b949e;margin-top:6px;line-height:1.4">${data.ai?.summary || ''}</div>
  `;
  document.documentElement.appendChild(toast);

  setTimeout(() => {
    if (toast.parentNode) {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }
  }, 5000);
}
