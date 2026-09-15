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

document.querySelectorAll('.vote-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    if (!currentData) return;
    const vote = btn.dataset.vote;
    const domain = currentData.domain;

    // Immediate visual feedback
    document.querySelectorAll('.vote-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    $('vote-feedback').textContent = 'Submitting vote…';
    show($('vote-feedback'));

    // Save vote locally so button stays highlighted on reopen
    const stored = await chrome.storage.local.get('my_votes');
    const myVotes = stored.my_votes || {};
    myVotes[domain] = vote;
    await chrome.storage.local.set({ my_votes: myVotes });

    // Submit vote
    chrome.runtime.sendMessage({ type: 'SUBMIT_VOTE', domain, vote }, async (resp) => {
      if (resp?.success || resp?.votes) {
        $('vote-feedback').textContent = `Vote recorded: ${vote}. Refreshing…`;

        // ── KEY FIX: fetch fresh analysis so bars reflect new vote ──
        chrome.runtime.sendMessage({ type: 'GET_FRESH_ANALYSIS', domain }, (fresh) => {
          if (fresh && fresh.community) {
            renderVotes(fresh.community);
            currentData = fresh; // Update local state
            $('vote-feedback').textContent = `Voted "${vote}" — thanks for helping the community!`;
            setTimeout(() => hide($('vote-feedback')), 3000);
          } else {
            // Fallback: update bars with vote response counts directly
            if (resp.votes) renderVotes(resp.votes);
            $('vote-feedback').textContent = `Voted "${vote}"!`;
            setTimeout(() => hide($('vote-feedback')), 3000);
          }
        });
      } else {
        $('vote-feedback').textContent = 'Vote failed — try again.';
        setTimeout(() => hide($('vote-feedback')), 2000);
      }
    });
  });
});

// ─── Report ──────────────────────────────────────────────────────────────────

$('report-btn').addEventListener('click', () => {
  const form = $('report-form');
  form.classList.contains('hidden') ? show(form) : hide(form);
});

$('report-submit').addEventListener('click', () => {
  if (!currentData) return;
  const expected = $('report-expected').value;
  const comment = $('report-comment').value;
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

// ─── Init ─────────────────────────────────────────────────────────────────────

chrome.runtime.sendMessage({ type: 'GET_ANALYSIS' }, (data) => {
  if (chrome.runtime.lastError || data?.error) {
    hide($('state-loading'));
    $('error-msg').textContent = data?.error || chrome.runtime.lastError?.message || 'Error';
    show($('state-error'));
    return;
  }
  if (data?.trustScore !== undefined) render(data);
});

$('retry-btn').addEventListener('click', () => {
  hide($('state-error'));
  show($('state-loading'));
  chrome.runtime.sendMessage({ type: 'GET_ANALYSIS' }, (data) => {
    if (data?.trustScore !== undefined) render(data);
  });
});