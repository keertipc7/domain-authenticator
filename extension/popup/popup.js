/**
 * Popup JS v2.1
 * Fix: after voting, fetch fresh analysis from Worker to update community bars
 */

const $ = id => document.getElementById(id);
const VERDICT_COLORS = { trusted:'#10b981', likely_safe:'#3b82f6', caution:'#f59e0b', suspicious:'#f97316', dangerous:'#ef4444' };
const VERDICT_LABELS = { trusted:'Trusted', likely_safe:'Likely safe', caution:'Use caution', suspicious:'Suspicious', dangerous:'Dangerous' };
const ACTION_LABELS = { allow:'Allowed', warn:'Warning shown', block:'Blocked' };
const SIGNAL_LABELS = { brandSimilarity:'Brand match', entropy:'Randomness', tld:'TLD risk', length:'Length', subdomain:'Subdomains', specialChars:'Characters' };

let currentData = null;

function show(el) { el.classList.remove('hidden'); }
function hide(el) { el.classList.add('hidden'); }
function dotColor(s) { return s >= 70 ? '#ef4444' : s >= 40 ? '#f59e0b' : s >= 15 ? '#3b82f6' : '#10b981'; }

function render(data) {
  currentData = data;
  hide($('state-loading'));
  hide($('state-error'));
  show($('state-results'));

  $('domain-name').textContent = data.domain;

  const circ = 2 * Math.PI * 52;
  const offset = circ - (data.trustScore / 100) * circ;
  const vc = VERDICT_COLORS[data.verdict] || '#6b7280';
  $('gauge-fill').style.strokeDashoffset = offset;
  $('gauge-fill').style.stroke = vc;
  $('trust-score').textContent = data.trustScore;
  $('trust-score').style.color = vc;
  $('verdict-badge').textContent = VERDICT_LABELS[data.verdict] || data.verdict;
  $('verdict-badge').style.color = vc;

  const ab = $('action-badge');
  ab.textContent = ACTION_LABELS[data.action] || data.action;
  ab.className = `action-badge action-${data.action}`;

  $('ai-summary').textContent = data.ai?.summary || 'Analysis completed.';
  $('ai-technical').textContent = data.ai?.technical_detail || '';

  $('ai-flags').innerHTML = '';
  (data.ai?.flags || []).forEach(f => {
    const el = document.createElement('span');
    el.className = 'flag'; el.textContent = f;
    $('ai-flags').appendChild(el);
  });

  $('ai-safe-reasons').innerHTML = '';
  (data.ai?.safe_reasons || []).forEach(r => {
    const el = document.createElement('span');
    el.className = 'safe-tag'; el.textContent = r;
    $('ai-safe-reasons').appendChild(el);
  });

  $('signals').innerHTML = '';
  if (data.signals && !data.allowlisted) {
    for (const [key, signal] of Object.entries(data.signals)) {
      if (key === 'note') continue;
      const row = document.createElement('div');
      row.className = 'signal';
      row.innerHTML = `
        <span class="signal-dot" style="background:${dotColor(signal.score)}"></span>
        <span class="signal-name">${SIGNAL_LABELS[key] || key}</span>
        <span class="signal-detail">${signal.detail}</span>
        <span class="signal-score">${signal.score}</span>
      `;
      $('signals').appendChild(row);
    }
  } else if (data.allowlisted) {
    $('signals').innerHTML = '<div style="font-size:12px;color:#8b949e;padding:4px 0">Domain is on the global allowlist.</div>';
  }

  renderVotes(data.community || { safe: 0, suspicious: 0, unsafe: 0, total: 0 });
  restoreVoteButtonState(data.domain);
}

function renderVotes(community) {
  const total = Math.max(community.total || 0, 1);
  $('vote-bars').innerHTML = [
    { label: 'Safe', key: 'safe', cls: 'safe', count: community.safe || 0 },
    { label: 'Suspicious', key: 'suspicious', cls: 'suspicious', count: community.suspicious || 0 },
    { label: 'Unsafe', key: 'unsafe', cls: 'unsafe', count: community.unsafe || 0 },
  ].map(b => `
    <div class="vote-bar-row">
      <span class="vote-bar-label">${b.label}</span>
      <div class="vote-bar-track"><div class="vote-bar-fill vote-bar-fill-${b.cls}" style="width:${Math.round((b.count/total)*100)}%"></div></div>
      <span class="vote-bar-count">${b.count}</span>
    </div>
  `).join('');
}

// Restore previously cast vote button state from storage
async function restoreVoteButtonState(domain) {
  const stored = await chrome.storage.local.get('my_votes');
  const myVotes = stored.my_votes || {};
  const myVote = myVotes[domain];
  if (myVote) {
    document.querySelectorAll('.vote-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.vote === myVote);
    });
  }
}

// ─── Vote buttons ─────────────────────────────────────────────────────────────

function renderVotes(community) {
  const total = community?.breakdown?.total || community?.total || 0;
  const safe       = community?.breakdown?.safe       || community?.safe       || 0;
  const suspicious = community?.breakdown?.suspicious || community?.suspicious || 0;
  const unsafe     = community?.breakdown?.unsafe     || community?.unsafe     || 0;
  const wtotal = Math.max(total, 1);

  // Confidence label
  let confidenceText = '';
  if (total === 0) confidenceText = 'No votes yet — be the first';
  else if (total === 1) confidenceText = '1 vote — need 2+ to activate signal';
  else if (total < 5)   confidenceText = `${total} votes — building confidence`;
  else                  confidenceText = `${total} votes · ${community.confidence || 0}% confidence`;

  $('vote-bars').innerHTML = `
    <div class="vote-confidence">${confidenceText}</div>
    ${renderBar('Safe',       safe,       total, 'safe')}
    ${renderBar('Suspicious', suspicious, total, 'suspicious')}
    ${renderBar('Unsafe',     unsafe,     total, 'unsafe')}
    ${community.verdict && community.verdict !== 'unrated' ? `
      <div class="vote-consensus">
        Community verdict: <span class="verdict-${community.verdict}">${verdictLabel(community.verdict)}</span>
        ${community.verdict === 'community_safe' ? '→ can downgrade a block to warn' : ''}
        ${community.verdict === 'community_unsafe' ? '→ can upgrade an allow to warn' : ''}
      </div>` : ''}
  `;
}

function renderBar(label, count, total, type) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return `
    <div class="vote-bar-row">
      <span class="vote-bar-label">${label}</span>
      <div class="vote-bar-track">
        <div class="vote-bar-fill vote-bar-fill-${type}" style="width:${pct}%"></div>
      </div>
      <span class="vote-bar-count">${count}</span>
    </div>`;
}

function verdictLabel(v) {
  return {
    community_safe:         'Mostly safe',
    community_leaning_safe: 'Leaning safe',
    community_mixed:        'Mixed signals',
    community_suspicious:   'Suspicious',
    community_unsafe:       'Unsafe',
    unrated:                'Unrated',
  }[v] || v;
}

// Vote buttons
document.querySelectorAll('.vote-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    if (!currentData) return;
    const vote = btn.dataset.vote;
    const domain = currentData.domain;

    // Optimistic UI — show immediately
    document.querySelectorAll('.vote-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    btn.textContent = '✓ ' + btn.textContent.replace('✓ ', '');

    // Persist vote choice locally (survives popup close)
    const stored = await chrome.storage.local.get('my_votes');
    const myVotes = stored.my_votes || {};
    myVotes[domain] = vote;
    await chrome.storage.local.set({ my_votes: myVotes });

    $('vote-feedback').textContent = 'Submitting…';
    show($('vote-feedback'));

    chrome.runtime.sendMessage({ type: 'SUBMIT_VOTE', domain, vote }, async (resp) => {
      if (resp?.success) {
        const weight = resp.yourWeight || 1;
        $('vote-feedback').textContent = weight > 1
          ? `Vote recorded (weight: ${weight}x — thanks for being an active reviewer!)`
          : 'Vote recorded — thank you!';

        // Refresh full analysis to get updated community object
        chrome.runtime.sendMessage({ type: 'GET_FRESH_ANALYSIS', domain }, (fresh) => {
          if (fresh?.community) {
            renderVotes(fresh.community);
            currentData = fresh;
          }
          setTimeout(() => hide($('vote-feedback')), 4000);
        });
      } else {
        $('vote-feedback').textContent = 'Vote failed — try again.';
        setTimeout(() => hide($('vote-feedback')), 2000);
      }
    });
  });
});

// Restore vote button state when popup opens
async function restoreVoteButtonState(domain) {
  const stored = await chrome.storage.local.get('my_votes');
  const myVote = (stored.my_votes || {})[domain];
  if (myVote) {
    document.querySelectorAll('.vote-btn').forEach(b => {
      if (b.dataset.vote === myVote) {
        b.classList.add('active');
        b.textContent = '✓ ' + b.textContent.replace('✓ ', '');
      }
    });
  }
}

/* Add these to extension/popup/popup.css */

/* Vote confidence line */
.vote-confidence {
  font-size: 11px;
  color: var(--t2);
  margin-bottom: 8px;
  font-style: italic;
}

/* Community consensus line */
.vote-consensus {
  font-size: 11px;
  color: var(--t2);
  margin-top: 8px;
  padding-top: 6px;
  border-top: 1px solid var(--b);
}

.verdict-community_safe         { color: var(--gn); font-weight: 500; }
.verdict-community_leaning_safe { color: var(--bl); font-weight: 500; }
.verdict-community_mixed        { color: var(--t2); font-weight: 500; }
.verdict-community_suspicious   { color: var(--am); font-weight: 500; }
.verdict-community_unsafe       { color: var(--rd); font-weight: 500; }

/* Active vote button — bolder border */
.vote-btn.active { border-width: 2px; font-weight: 700; }