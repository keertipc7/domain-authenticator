/**
 * Popup JS v2.3 — fixed: removed duplicate renderVotes, added missing init block
 */

const $ = id => document.getElementById(id);

const VERDICT_COLORS = { trusted:'#10b981', likely_safe:'#3b82f6', caution:'#f59e0b', suspicious:'#f97316', dangerous:'#ef4444' };
const VERDICT_LABELS = { trusted:'Trusted', likely_safe:'Likely safe', caution:'Use caution', suspicious:'Suspicious', dangerous:'Dangerous' };
const ACTION_LABELS  = { allow:'Allowed', warn:'Warning shown', block:'Blocked' };
const SIGNAL_LABELS  = { brandSimilarity:'Brand match', entropy:'Randomness', tld:'TLD risk', length:'Length', subdomain:'Subdomains', specialChars:'Characters' };

let currentData = null;

function show(el) { el.classList.remove('hidden'); }
function hide(el) { el.classList.add('hidden'); }
function dotColor(s) { return s >= 70 ? '#ef4444' : s >= 40 ? '#f59e0b' : s >= 15 ? '#3b82f6' : '#10b981'; }

// ─── Render full result ───────────────────────────────────────────────────────

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

  $('ai-summary').textContent   = data.ai?.summary || 'Analysis completed.';
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

// ─── Community votes ──────────────────────────────────────────────────────────

function renderVotes(community) {
  const total      = community?.breakdown?.total      || community?.total      || 0;
  const safe       = community?.breakdown?.safe       || community?.safe       || 0;
  const suspicious = community?.breakdown?.suspicious || community?.suspicious || 0;
  const unsafe     = community?.breakdown?.unsafe     || community?.unsafe     || 0;

  let confidenceText;
  if      (total === 0) confidenceText = 'No votes yet — be the first';
  else if (total === 1) confidenceText = '1 vote — need 2+ to activate signal';
  else if (total < 5)   confidenceText = `${total} votes — building confidence`;
  else                  confidenceText = `${total} votes · ${community.confidence || 0}% confidence`;

  const consensusHTML = community.verdict && community.verdict !== 'unrated' && community.verdict !== 'allowlisted' ? `
    <div class="vote-consensus">
      Community verdict: <span class="verdict-${community.verdict}">${verdictLabel(community.verdict)}</span>
      ${community.verdict === 'community_safe'   ? ' → can downgrade a block to warn' : ''}
      ${community.verdict === 'community_unsafe' ? ' → can upgrade an allow to warn'  : ''}
    </div>` : '';

  $('vote-bars').innerHTML = `
    <div class="vote-confidence">${confidenceText}</div>
    ${renderBar('Safe',       safe,       total, 'safe')}
    ${renderBar('Suspicious', suspicious, total, 'suspicious')}
    ${renderBar('Unsafe',     unsafe,     total, 'unsafe')}
    ${consensusHTML}
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

async function restoreVoteButtonState(domain) {
  const stored  = await chrome.storage.local.get('my_votes');
  const myVote  = (stored.my_votes || {})[domain];
  if (!myVote) return;
  document.querySelectorAll('.vote-btn').forEach(b => {
    if (b.dataset.vote === myVote) {
      b.classList.add('active');
      b.textContent = '✓ ' + b.textContent.replace('✓ ', '');
    }
  });
}

// ─── Vote buttons ─────────────────────────────────────────────────────────────

document.querySelectorAll('.vote-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    if (!currentData) return;
    const vote   = btn.dataset.vote;
    const domain = currentData.domain;

    document.querySelectorAll('.vote-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    btn.textContent = '✓ ' + btn.textContent.replace('✓ ', '');

    const stored  = await chrome.storage.local.get('my_votes');
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

        chrome.runtime.sendMessage({ type: 'GET_FRESH_ANALYSIS', domain }, (fresh) => {
          if (fresh?.community) { renderVotes(fresh.community); currentData = fresh; }
          setTimeout(() => hide($('vote-feedback')), 4000);
        });
      } else {
        $('vote-feedback').textContent = 'Vote failed — try again.';
        setTimeout(() => hide($('vote-feedback')), 2000);
      }
    });
  });
});

// ─── Report AI mistake ────────────────────────────────────────────────────────

$('report-btn').addEventListener('click', () => {
  const form = $('report-form');
  form.classList.contains('hidden') ? show(form) : hide(form);
});

$('report-submit').addEventListener('click', () => {
  if (!currentData) return;
  const expected = $('report-expected').value;
  const comment  = $('report-comment').value;
  if (!expected) { $('report-expected').style.borderColor = '#ef4444'; return; }

  chrome.runtime.sendMessage({
    type: 'REPORT_MISTAKE',
    data: { domain: currentData.domain, expected_verdict: expected, actual_verdict: currentData.verdict, comment },
  }, (resp) => {
    if (resp?.success) {
      hide($('report-form'));
      $('report-btn').textContent = '✓ Report submitted — thank you!';
      $('report-btn').disabled = true;
    }
  });
});

// ─── Init — this was missing, causing the eternal loading state ───────────────

chrome.runtime.sendMessage({ type: 'GET_ANALYSIS' }, (data) => {
  if (chrome.runtime.lastError) {
    hide($('state-loading'));
    $('error-msg').textContent = chrome.runtime.lastError.message || 'Extension error';
    show($('state-error'));
    return;
  }
  if (!data) {
    hide($('state-loading'));
    $('error-msg').textContent = 'No response from background script — try reloading the extension';
    show($('state-error'));
    return;
  }
  if (data.error) {
    hide($('state-loading'));
    $('error-msg').textContent = data.error;
    show($('state-error'));
    return;
  }
  if (data.trustScore !== undefined) {
    render(data);
  }
});

$('retry-btn').addEventListener('click', () => {
  hide($('state-error'));
  show($('state-loading'));
  chrome.runtime.sendMessage({ type: 'GET_ANALYSIS' }, (data) => {
    if (data?.trustScore !== undefined) render(data);
    else {
      $('error-msg').textContent = data?.error || 'Analysis failed';
      hide($('state-loading'));
      show($('state-error'));
    }
  });
});