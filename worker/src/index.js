/**
 * Domain Authenticator v2.1 — Cloudflare Worker
 * Fixes: AI response parsing, scoring weights, digit-substitution detection,
 *        combo-signal overrides, and stricter blocking thresholds.
 */

// ─── Brand & TLD data ───────────────────────────────────────────────────────

const KNOWN_BRANDS = [
  'google','facebook','amazon','apple','microsoft','netflix','paypal',
  'instagram','twitter','linkedin','whatsapp','telegram','github',
  'dropbox','adobe','salesforce','stripe','shopify','coinbase',
  'binance','chase','bankofamerica','wellsfargo','citibank','hsbc',
  'cloudflare','aws','azure','slack','zoom','spotify','uber',
  'airbnb','reddit','discord','steam','walmart','ebay','fedex',
  'dhl','ups','usps','irs','gmail','outlook','office','onedrive',
  'icloud','yahoo','bing','linkedin','tiktok','snapchat','pinterest',
];

// Digit/homoglyph substitution map — catches g00gle, m1crosoft, paypa1, etc.
const SUBSTITUTIONS = {
  '0':'o','1':'i','3':'e','4':'a','5':'s','6':'g','7':'t','8':'b','9':'g',
  '@':'a','$':'s','!':'i','|':'i','vv':'w',
};

const HIGH_RISK_TLDS = [
  'xyz','top','buzz','club','work','surf','tk','ml','ga','cf','gq',
  'cam','icu','fun','monster','click','link','rest','sbs','cyou','pw',
  'cc','win','bid','stream','download','loan','racing','party','trade',
  'date','review','accountant','science','faith','cricket',
];
const MEDIUM_RISK_TLDS = ['info','biz','online','site','space','website','store'];
const TRUSTED_TLDS = ['com','org','net','edu','gov','mil','int','co.uk','org.uk','ac.uk','de','fr','jp','au','ca','io','dev','app'];

const SAFE_DOMAINS = new Set([
  'google.com','youtube.com','facebook.com','amazon.com','wikipedia.org',
  'twitter.com','x.com','instagram.com','linkedin.com','reddit.com',
  'github.com','stackoverflow.com','apple.com','microsoft.com','netflix.com',
  'cloudflare.com','dash.cloudflare.com','developers.cloudflare.com','blog.cloudflare.com',
  'workers.cloudflare.com','discord.com','whatsapp.com','zoom.us','spotify.com',
  'paypal.com','stripe.com','slack.com','app.slack.com','files.slack.com',
  'hooks.slack.com','api.slack.com','notion.so','figma.com',
  'vercel.com','netlify.com','medium.com','openai.com','anthropic.com',
  'docs.google.com','drive.google.com','mail.google.com','gmail.com',
  'outlook.com','office.com','live.com','hotmail.com','bing.com',
  'atlassian.com','jira.atlassian.com','confluence.atlassian.com',
  'dropbox.com','box.com','salesforce.com','hubspot.com',
  'zoom.us','webex.com','teams.microsoft.com','meet.google.com',
]);

// ─── Heuristic engine ───────────────────────────────────────────────────────

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[m][n];
}

function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((s, f) => { const p = f / len; return s + p * Math.log2(p); }, 0);
}

// Normalise digit/homoglyph substitutions: g00gle → google
function normaliseSubstitutions(str) {
  let result = str.toLowerCase();
  // Multi-char first
  result = result.replace(/vv/g, 'w');
  for (const [sub, char] of Object.entries(SUBSTITUTIONS)) {
    if (sub.length === 1) result = result.split(sub).join(char);
  }
  return result;
}

// Detect digit substitution specifically — returns which brand was targeted
function checkDigitSubstitution(rawName) {
  const normalised = normaliseSubstitutions(rawName);
  if (normalised === rawName) return null; // No substitutions found

  for (const brand of KNOWN_BRANDS) {
    if (normalised.includes(brand) || levenshtein(normalised, brand) <= 1) {
      return { brand, original: rawName, normalised };
    }
  }
  return null;
}

function checkBrandSimilarity(domain) {
  const parts = domain.split('.');

  // If this is a subdomain of an allowlisted domain, skip entirely
  if (parts.length >= 2) {
    const base = parts.slice(-2).join('.');
    if (SAFE_DOMAINS.has(base) || SAFE_DOMAINS.has(domain)) {
      return { score: 0, brand: null, distance: 0, detail: 'Subdomain of a trusted domain', type: 'safe_subdomain' };
    }
  }

  const rawName = parts[0].toLowerCase();

  // 1. Check digit/homoglyph substitution first (g00gle, m1crosoft)
  const digitSub = checkDigitSubstitution(rawName);
  if (digitSub) {
    return {
      score: 98, brand: digitSub.brand, distance: 0,
      detail: `"${rawName}" uses digit/character substitution to impersonate "${digitSub.brand}" — a textbook phishing technique`,
      type: 'digit_substitution',
    };
  }

  // 2. Strip non-alpha for Levenshtein comparison
  const cleanName = rawName.replace(/[-_0-9]/g, '');
  let closestBrand = null, minDist = Infinity;

  for (const brand of KNOWN_BRANDS) {
    if (cleanName === brand) return { score: 0, brand: null, distance: 0, detail: 'Exact brand match', type: 'exact' };

    // Contains brand with extra chars — brand must be 5+ chars to avoid false positives
    if (brand.length >= 5 && rawName.includes(brand) && rawName !== brand) {
      return { score: 85, brand, distance: 0, detail: `Contains "${brand}" with extra characters — classic phishing pattern`, type: 'contains' };
    }

    const dist = levenshtein(cleanName, brand);

    // Guard: only flag if both strings are similar in length (within 3 chars)
    // This prevents 'slack' (5) matching 'apple' (5) with dist=2 being flagged
    // when they are completely different words
    const lengthDiff = Math.abs(cleanName.length - brand.length);
    if (dist < minDist && lengthDiff <= 2) {
      minDist = dist;
      closestBrand = brand;
    }
  }

  // For distance-2 matches, require brand to be 6+ chars to reduce false positives
  // Short words like 'slack','apple','chase' are too short for distance-2 to be meaningful
  if (minDist === 1 && closestBrand) {
    return { score: 92, brand: closestBrand, distance: 1, detail: `1 character away from "${closestBrand}" — likely typosquatting`, type: 'typosquat_1' };
  }
  if (minDist === 2 && closestBrand && closestBrand.length >= 6) {
    return { score: 65, brand: closestBrand, distance: 2, detail: `2 characters away from "${closestBrand}" — possible impersonation`, type: 'typosquat_2' };
  }

  return { score: 0, brand: null, distance: minDist, detail: 'No brand similarity detected', type: 'clean' };
}

function checkEntropy(domain) {
  const name = domain.split('.')[0];
  const e = shannonEntropy(name);
  if (e > 4.2) return { score: 85, value: +e.toFixed(2), detail: 'Very high randomness — likely algorithmically generated (DGA)' };
  if (e > 3.8) return { score: 60, value: +e.toFixed(2), detail: 'High randomness — unusual for legitimate domains' };
  if (e > 3.3) return { score: 25, value: +e.toFixed(2), detail: 'Above-average randomness' };
  return { score: 0, value: +e.toFixed(2), detail: 'Normal character distribution' };
}

function checkTLD(domain) {
  const tld = domain.split('.').slice(1).join('.');
  if (HIGH_RISK_TLDS.includes(tld)) return { score: 92, tld, risk: 'high', detail: `".${tld}" is heavily abused in phishing campaigns — treat with extreme caution` };
  if (MEDIUM_RISK_TLDS.includes(tld)) return { score: 50, tld, risk: 'medium', detail: `".${tld}" has elevated abuse rates` };
  if (TRUSTED_TLDS.includes(tld)) return { score: 0, tld, risk: 'low', detail: `".${tld}" is a well-established trusted TLD` };
  return { score: 20, tld, risk: 'neutral', detail: `".${tld}" — no strong signal either way` };
}

function checkLength(domain) {
  const name = domain.split('.')[0];
  if (name.length > 30) return { score: 70, length: name.length, detail: 'Unusually long — often used to obscure malicious intent' };
  if (name.length > 20) return { score: 40, length: name.length, detail: 'Longer than typical legitimate domains' };
  if (name.length > 15) return { score: 15, length: name.length, detail: 'Slightly long but within normal range' };
  return { score: 0, length: name.length, detail: 'Normal length' };
}

function checkSubdomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length > 3) {
    const subs = parts.slice(0, -2).join('.');
    for (const brand of KNOWN_BRANDS) {
      if (subs.includes(brand)) return { score: 97, detail: `Brand "${brand}" used as subdomain — classic phishing technique (e.g. paypal.com.evil.xyz)` };
    }
    if (parts.length > 4) return { score: 55, detail: 'Excessive subdomain depth — unusual for legitimate sites' };
    return { score: 20, detail: 'Multiple subdomains present' };
  }
  return { score: 0, detail: 'Normal subdomain structure' };
}

function checkSpecialChars(domain) {
  const name = domain.split('.')[0];
  const hyphens = (name.match(/-/g) || []).length;
  const digits = (name.match(/\d/g) || []).length;
  let score = 0; const issues = [];
  if (hyphens >= 3) { score += 55; issues.push(`${hyphens} hyphens`); }
  else if (hyphens >= 2) { score += 30; issues.push(`${hyphens} hyphens`); }
  if (digits >= 3) { score += 40; issues.push(`${digits} digits`); }
  else if (digits >= 1) { score += 15; issues.push(`${digits} digit(s)`); }
  if (name.startsWith('-') || name.endsWith('-')) { score += 40; issues.push('leading/trailing hyphen'); }
  return { score: Math.min(score, 95), detail: issues.length ? `Suspicious characters: ${issues.join(', ')}` : 'Clean character usage' };
}

// ─── Combo signal override — catches cases the weighted average misses ───────

function checkCombinationOverrides(heuristics) {
  const brand = heuristics.brandSimilarity;
  const tld = heuristics.tld;
  const subdomain = heuristics.subdomain;

  const overrides = [];

  // Digit substitution of a known brand = always critical
  if (brand.type === 'digit_substitution') {
    overrides.push({ level: 'critical', reason: `Digit substitution attack targeting "${brand.brand}" — this is never legitimate` });
  }

  // Brand impersonation + high-risk TLD = critical (e.g. g00gle.xyz)
  if (brand.score >= 60 && tld.risk === 'high') {
    overrides.push({ level: 'critical', reason: `Brand impersonation combined with high-risk TLD — extremely high phishing probability` });
  }

  // Brand in subdomain + any risk TLD = critical
  if (subdomain.score >= 90) {
    overrides.push({ level: 'critical', reason: `Brand name used as subdomain to deceive users — this is a known attack pattern` });
  }

  // Typosquat 1-char + any risk signal
  if (brand.type === 'typosquat_1' && (tld.risk === 'high' || tld.risk === 'medium')) {
    overrides.push({ level: 'critical', reason: `1-character typosquat of "${brand.brand}" on a suspicious TLD` });
  }

  return overrides;
}

// ─── Community voting ───────────────────────────────────────────────────────

async function getCommunityVotes(env, domain) {
  try {
    const data = await env.COMMUNITY_VOTES.get(`votes:${domain}`, 'json');
    return data || { safe: 0, suspicious: 0, unsafe: 0, wsafe: 0, wsuspicious: 0, wunsafe: 0, total: 0, voters: {} };
  } catch {
    return { safe: 0, suspicious: 0, unsafe: 0, wsafe: 0, wsuspicious: 0, wunsafe: 0, total: 0, voters: {} };
  }
}

function communityScore(votes) {
  // Normalise — handle old format entries that don't have weighted fields
  const safe       = votes.safe       || 0;
  const suspicious = votes.suspicious || 0;
  const unsafe     = votes.unsafe     || 0;
  const total      = votes.total      || 0;
  // Use weighted totals if present, fall back to raw counts
  const wsafe       = votes.wsafe       || safe;
  const wsuspicious = votes.wsuspicious || suspicious;
  const wunsafe     = votes.wunsafe     || unsafe;
  const wtotal      = wsafe + wsuspicious + wunsafe;

  if (total === 0 || wtotal === 0) {
    return { score: 0, confidence: 0, detail: 'No community votes yet', verdict: 'unrated', breakdown: { safe, suspicious, unsafe, total } };
  }

  const safeRatio       = wsafe       / wtotal;
  const unsafeRatio     = wunsafe     / wtotal;
  const suspiciousRatio = wsuspicious / wtotal;
  const confidence      = Math.min(100, total * 10);

  let score, verdict;
  if (unsafeRatio >= 0.6)      { score = 88 + Math.min(10, total); verdict = 'community_unsafe'; }
  else if (unsafeRatio >= 0.4) { score = 65;  verdict = 'community_suspicious'; }
  else if (safeRatio >= 0.6)   { score = 0;   verdict = 'community_safe'; }
  else if (safeRatio >= 0.4)   { score = 10;  verdict = 'community_leaning_safe'; }
  else                         { score = 30;  verdict = 'community_mixed'; }

  return {
    score, confidence, verdict,
    detail: `${total} vote${total !== 1 ? 's' : ''}: ${safe} safe, ${suspicious} suspicious, ${unsafe} unsafe`,
    breakdown: { safe, suspicious, unsafe, total },
  };
}

// ─── Workers AI ─────────────────────────────────────────────────────────────

async function analyzeWithAI(env, domain, heuristics, community, overrides) {
  const overrideContext = overrides.length
    ? `CRITICAL OVERRIDE SIGNALS DETECTED:\n${overrides.map(o => `- ${o.reason}`).join('\n')}\n\n`
    : '';

  const prompt = `${overrideContext}You are a senior cybersecurity analyst at Cloudflare. Analyze this domain for phishing/impersonation risk.

Domain: ${domain}

Heuristic signals:
- Brand similarity: ${heuristics.brandSimilarity.detail} [score: ${heuristics.brandSimilarity.score}/100]
- Entropy: ${heuristics.entropy.detail} [score: ${heuristics.entropy.score}/100]
- TLD risk: ${heuristics.tld.detail} [score: ${heuristics.tld.score}/100]
- Length: ${heuristics.length.detail} [score: ${heuristics.length.score}/100]
- Subdomain abuse: ${heuristics.subdomain.detail} [score: ${heuristics.subdomain.score}/100]
- Special chars: ${heuristics.specialChars.detail} [score: ${heuristics.specialChars.score}/100]
- Community votes: ${community.detail}

Be direct and confident. If multiple high-risk signals are present, rate it critical. Do not hedge.

Respond with ONLY valid JSON (no markdown):
{
  "risk": "low" | "medium" | "high" | "critical",
  "confidence": 0-100,
  "summary": "One direct sentence for a non-technical user — state clearly if this is dangerous and why",
  "technical_detail": "Two sentences explaining the specific attack pattern detected",
  "recommendation": "allow" | "caution" | "block",
  "flags": ["specific threat indicators"],
  "safe_reasons": ["reasons this might be legitimate, if any — leave empty if none"]
}`;

  try {
    const response = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
      messages: [
        { role: 'system', content: 'You are a cybersecurity analyst. Respond only with valid JSON. No markdown, no backticks, no explanation outside the JSON.' },
        { role: 'user', content: prompt },
      ],
      max_tokens: 400,
      temperature: 0.05, // Very low temp = more deterministic, less hedging
    });

    // Workers AI returns { response: string } — extract text correctly
    const raw = typeof response === 'string' ? response : (response?.response || JSON.stringify(response));
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in AI response');

    const parsed = JSON.parse(jsonMatch[0]);

    // If overrides exist, enforce minimum risk level
    if (overrides.some(o => o.level === 'critical')) {
      parsed.risk = 'critical';
      parsed.recommendation = 'block';
      parsed.confidence = Math.max(parsed.confidence || 0, 90);
    }

    return {
      risk: parsed.risk || 'high',
      confidence: parsed.confidence || 85,
      summary: parsed.summary || 'This domain has been flagged as dangerous.',
      technical_detail: parsed.technical_detail || '',
      recommendation: parsed.recommendation || 'block',
      flags: parsed.flags || [],
      safe_reasons: parsed.safe_reasons || [],
      ai_powered: true,
    };
  } catch (err) {
    console.error('AI error:', err.message);
    return smartFallback(heuristics, overrides);
  }
}

// Smart fallback — uses combo overrides and signal severity, not just counts
function smartFallback(heuristics, overrides) {
  if (overrides.some(o => o.level === 'critical')) {
    return {
      risk: 'critical',
      confidence: 88,
      summary: `This domain is impersonating a well-known brand using deceptive techniques — do not proceed.`,
      technical_detail: overrides.map(o => o.reason).join(' '),
      recommendation: 'block',
      flags: overrides.map(o => o.reason),
      safe_reasons: [],
      ai_powered: false,
    };
  }
  const maxScore = Math.max(...Object.values(heuristics).map(h => h.score || 0));
  const highSignals = Object.values(heuristics).filter(h => h.score >= 60);
  if (highSignals.length >= 2 || maxScore >= 90) {
    return { risk: 'high', confidence: 75, summary: 'Multiple serious risk signals detected — this domain is likely malicious.', technical_detail: 'Combined heuristic analysis flagged brand impersonation and/or high-risk TLD patterns.', recommendation: 'block', flags: highSignals.map(h => h.detail), safe_reasons: [], ai_powered: false };
  }
  if (highSignals.length === 1) {
    return { risk: 'medium', confidence: 60, summary: 'Risk signal detected — proceed with caution.', technical_detail: highSignals[0].detail, recommendation: 'caution', flags: [highSignals[0].detail], safe_reasons: [], ai_powered: false };
  }
  return { risk: 'low', confidence: 50, summary: 'No significant risk signals detected.', technical_detail: 'No heuristic signals exceeded risk threshold.', recommendation: 'allow', flags: [], safe_reasons: ['No red flags detected'], ai_powered: false };
}

// ─── Scoring engine ─────────────────────────────────────────────────────────

function computeScore(heuristics, aiResult, community, overrides) {
  // Combo overrides short-circuit scoring — always critical
  if (overrides.some(o => o.level === 'critical')) {
    return { trustScore: 4, riskScore: 96, verdict: 'dangerous', action: 'block' };
  }

  const weights = {
    brandSimilarity: 0.30, // Increased — brand impersonation is the #1 signal
    tld: 0.18,             // Increased — TLD is highly predictive
    entropy: 0.10,
    subdomain: 0.10,
    specialChars: 0.05,
    length: 0.05,
    ai: 0.22,              // AI gets significant weight when available
  };

  const aiScoreMap = { low: 0, medium: 45, high: 80, critical: 97, unknown: 40 };
  const aiScore = aiScoreMap[aiResult.risk] || 40;

  // Community modifies final score if confidence is high enough
  let communityAdjust = 0;
  if (community.confidence >= 30) {
    communityAdjust = (community.score - 50) * 0.15; // +/- 7.5 max adjustment
  }

  const baseRisk =
    heuristics.brandSimilarity.score * weights.brandSimilarity +
    heuristics.tld.score * weights.tld +
    heuristics.entropy.score * weights.entropy +
    heuristics.subdomain.score * weights.subdomain +
    heuristics.specialChars.score * weights.specialChars +
    heuristics.length.score * weights.length +
    aiScore * weights.ai;

  const riskScore = Math.round(Math.min(100, baseRisk + communityAdjust));
  const trustScore = 100 - riskScore;

  // Stricter thresholds — bias toward safety
  let verdict, action;
  if (trustScore >= 75) { verdict = 'trusted'; action = 'allow'; }
  else if (trustScore >= 58) { verdict = 'likely_safe'; action = 'allow'; }
  else if (trustScore >= 42) { verdict = 'caution'; action = 'warn'; }
  else if (trustScore >= 22) { verdict = 'suspicious'; action = 'block'; }
  else { verdict = 'dangerous'; action = 'block'; }

  // AI block recommendation upgrades warn → block
  if (aiResult.recommendation === 'block' && action === 'warn') action = 'block';

  // Strong community consensus can shift one level
  if (community.verdict === 'community_safe' && community.confidence >= 60 && action === 'block') action = 'warn';
  if (community.verdict === 'community_unsafe' && community.confidence >= 60 && action === 'allow') action = 'warn';

  return { trustScore, riskScore, verdict, action };
}

// ─── Route handlers ─────────────────────────────────────────────────────────

async function handleAnalyze(request, env) {
  const body = await request.json();
  const domain = (body.domain || '').toLowerCase().replace(/^www\./, '').trim();
  if (!domain) return jsonResp({ error: 'Missing "domain"' }, 400);

  // Allowlist
  if (SAFE_DOMAINS.has(domain)) {
    return jsonResp({
      domain, trustScore: 98, riskScore: 2, verdict: 'trusted', action: 'allow',
      cached: false, allowlisted: true, signals: {},
      ai: { risk: 'low', confidence: 99, summary: 'This is a verified, well-known platform.', technical_detail: 'Domain is on the global allowlist of verified major platforms.', recommendation: 'allow', flags: [], safe_reasons: ['Major verified platform'], ai_powered: false },
      community: { safe: 0, suspicious: 0, unsafe: 0, total: 0, verdict: 'allowlisted' },
      overrides: [], analyzedAt: new Date().toISOString(),
    });
  }

  // Check cache (but skip cache if force=true)
  const force = body.force === true;
  const cacheKey = `v2:${domain}`;
  if (!force) {
    const cached = await env.DOMAIN_CACHE.get(cacheKey, 'json');
    if (cached) return jsonResp({ ...cached, cached: true });
  }

  // Run all analyses in parallel where possible
  const heuristics = {
    brandSimilarity: checkBrandSimilarity(domain),
    entropy: checkEntropy(domain),
    tld: checkTLD(domain),
    length: checkLength(domain),
    subdomain: checkSubdomain(domain),
    specialChars: checkSpecialChars(domain),
  };

  const overrides = checkCombinationOverrides(heuristics);
  const votes = await getCommunityVotes(env, domain);
  const community = communityScore(votes);

  // Run AI in parallel with scoring prep
  const aiResult = await analyzeWithAI(env, domain, heuristics, community, overrides);
  const { trustScore, riskScore, verdict, action } = computeScore(heuristics, aiResult, community, overrides);

  const result = {
    domain, trustScore, riskScore, verdict, action,
    cached: false, allowlisted: false,
    signals: heuristics,
    ai: aiResult,
    overrides,
    community: { ...votes, verdict: community.verdict, communityScore: community.score, confidence: community.confidence },
    analyzedAt: new Date().toISOString(),
  };

  // Cache for 6 hours (shorter than before — domain reputation can change)
  await env.DOMAIN_CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 21600 });
  return jsonResp(result);
}

async function handleVote(request, env) {
  const { domain, vote, userId } = await request.json();
  if (!domain || !['safe', 'suspicious', 'unsafe'].includes(vote)) {
    return jsonResp({ error: 'Need domain + vote (safe|suspicious|unsafe)' }, 400);
  }
  const hostname = domain.toLowerCase().replace(/^www\./, '').trim();
  const key = `votes:${hostname}`;
  const existing = await env.COMMUNITY_VOTES.get(key, 'json') || { safe: 0, suspicious: 0, unsafe: 0, total: 0, voters: {} };

  const uid = userId || 'anon_' + Math.random().toString(36).slice(2, 8);
  const prev = existing.voters?.[uid];
  if (prev) { existing[prev] = Math.max(0, existing[prev] - 1); existing.total = Math.max(0, existing.total - 1); }
  existing[vote]++; existing.total++;
  existing.voters = existing.voters || {};
  existing.voters[uid] = vote;

  await env.COMMUNITY_VOTES.put(key, JSON.stringify(existing));
  await env.DOMAIN_CACHE.delete(`v2:${hostname}`); // Bust cache on new vote

  return jsonResp({ success: true, domain: hostname, votes: { safe: existing.safe, suspicious: existing.suspicious, unsafe: existing.unsafe, total: existing.total } });
}

async function handleGetVotes(request, env) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get('domain') || '').toLowerCase().replace(/^www\./, '').trim();
  if (!domain) return jsonResp({ error: 'Missing ?domain=' }, 400);
  return jsonResp({ domain, votes: await getCommunityVotes(env, domain) });
}

async function handleReport(request, env) {
  const { domain, expected_verdict, actual_verdict, comment } = await request.json();
  if (!domain) return jsonResp({ error: 'Missing domain' }, 400);
  const hostname = domain.toLowerCase().replace(/^www\./, '').trim();
  const key = `reports:${hostname}`;
  const reports = await env.COMMUNITY_VOTES.get(key, 'json') || [];
  reports.push({ expected_verdict, actual_verdict, comment, timestamp: new Date().toISOString() });
  await env.COMMUNITY_VOTES.put(key, JSON.stringify(reports), { expirationTtl: 604800 });
  return jsonResp({ success: true, message: 'Report submitted — thank you for helping improve accuracy' });
}

function jsonResp(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' },
  });
}

// ─── Router ─────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
    const url = new URL(request.url);
    try {
      if (url.pathname === '/analyze' && request.method === 'POST') return handleAnalyze(request, env);
      if (url.pathname === '/vote' && request.method === 'POST') return handleVote(request, env);
      if (url.pathname === '/votes' && request.method === 'GET') return handleGetVotes(request, env);
      if (url.pathname === '/report' && request.method === 'POST') return handleReport(request, env);
      return jsonResp({ service: 'Domain Authenticator v2.1', endpoints: ['POST /analyze', 'POST /vote', 'GET /votes?domain=', 'POST /report'] });
    } catch (err) {
      console.error(err);
      return jsonResp({ error: 'Internal error', message: err.message }, 500);
    }
  },
};