# Domain Authenticator

> Real-time domain trust scoring — Chrome extension powered by Cloudflare Workers AI

A Chrome extension that analyzes every domain you visit, blocks dangerous sites before you interact with them, and shows a detailed AI-powered trust breakdown. Built on Cloudflare's edge infrastructure — Workers, Workers AI, and Workers KV.

![Cloudflare Workers AI](https://img.shields.io/badge/Cloudflare-Workers%20AI-F6821F?logo=cloudflare&logoColor=white)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-4285F4?logo=googlechrome&logoColor=white)
![Free Tier](https://img.shields.io/badge/Cloudflare-Free%20Tier-10B981)

---

## What it does

| Feature | Description |
|---|---|
| **Auto-analyze on every navigation** | Scores every domain the moment you visit — no manual action needed |
| **Block dangerous sites** | Full-screen block overlay with AI reasoning and a "proceed anyway" escape hatch |
| **Warn on suspicious sites** | Amber banner injected at the top of the page, auto-dismisses after 10s |
| **Detailed popup** | Trust gauge, per-signal breakdown, AI plain-English explanation |
| **Community voting** | Mark sites Safe / Suspicious / Unsafe — feeds back into scoring |
| **Right-click any link** | Analyze a URL before you click it |
| **Report AI mistakes** | Helps improve accuracy over time |

---

## Architecture

```
┌─────────────────────────────────────────┐
│         Chrome Extension (MV3)          │
│                                         │
│  background.js  ──────── content.js     │
│  (service worker)        (block/warn)   │
│       │                                 │
│  popup/popup.js                         │
│  (analysis dashboard)                   │
└──────────────┬──────────────────────────┘
               │ POST /analyze
               ▼
┌─────────────────────────────────────────┐
│       Cloudflare Worker (Edge API)      │
│                                         │
│  ┌─────────────────┐  ┌──────────────┐ │
│  │ Heuristic engine │  │ Workers AI   │ │
│  │ - Digit sub      │  │ Llama 3.1 8B │ │
│  │ - Typosquatting  │  │ (semantic    │ │
│  │ - TLD risk       │  │  analysis)   │ │
│  │ - Entropy        │  └──────────────┘ │
│  │ - Combo override │                   │
│  └─────────────────┘                   │
│                                         │
│  ┌─────────────────┐  ┌──────────────┐ │
│  │  DOMAIN_CACHE   │  │  COMMUNITY   │ │
│  │  Workers KV     │  │  VOTES KV    │ │
│  │  (6h TTL)       │  │              │ │
│  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────┘
```

---

## Scoring model

The trust score (0–100) is computed from six heuristic signals plus AI inference:

| Signal | Weight | What it catches |
|---|---|---|
| Brand similarity | 30% | Typosquatting, digit substitution (`g00gle`), contains-brand patterns |
| Workers AI verdict | 22% | Semantic patterns heuristics miss |
| TLD risk | 18% | `.xyz`, `.top`, `.buzz` and 30+ other high-abuse TLDs |
| Entropy | 10% | DGA-generated random-looking domains |
| Subdomain abuse | 10% | `paypal.com.evil.xyz` patterns |
| Special characters | 5% | Hyphen/digit abuse |
| Length | 5% | Unusually long domains |

**Combo overrides** short-circuit the weighted average — digit substitution of a known brand, or brand impersonation + high-risk TLD, immediately forces `trustScore < 5` and `action: block` regardless of other signals.

### Verdict thresholds

| Trust score | Verdict | Action |
|---|---|---|
| 75–100 | Trusted | Allow |
| 58–74 | Likely safe | Allow |
| 42–57 | Caution | Warn (banner) |
| 22–41 | Suspicious | Block |
| 0–21 | Dangerous | Block |

---

## Community voting system

Every user gets a persistent anonymous ID stored in `chrome.storage.local`. Votes are stored in a dedicated `COMMUNITY_VOTES` KV namespace. Key behaviors:

- One vote per user per domain (can change vote)
- Voting invalidates the KV cache so the next analysis reflects the new verdict
- Community consensus can shift the action one level (strong safe consensus downgrades block → warn; strong unsafe consensus upgrades allow → warn)
- Confidence scales with vote count — low-volume votes have minimal impact

---

## Free tier feasibility

| Resource | Free limit | Usage |
|---|---|---|
| Workers requests | 100K/day | ~50K (200 domains × 250 users) |
| Workers AI | 10K neurons/day | ~5K (cached after first analysis) |
| KV reads | 100K/day | ~45K (85%+ cache hit rate) |
| KV writes | 1K/day | ~500 (only new/uncached domains) |

---

## Project structure

```
├── worker/
│   ├── src/index.js        # Cloudflare Worker — full analysis engine
│   ├── wrangler.toml       # Config — add your KV namespace IDs here
│   └── package.json
├── extension/
│   ├── manifest.json       # Chrome Manifest V3
│   ├── background.js       # Service worker — navigation, badge, blocking
│   ├── content.js          # Block overlay + warning banner injection
│   ├── content.css         # Injected UI styles
│   ├── icons/              # Extension icons
│   └── popup/
│       ├── popup.html      # Analysis dashboard
│       ├── popup.css
│       └── popup.js
└── docs/
    └── index.html          # Live demo page (Cloudflare Pages)
```

---

## Deploy

### Prerequisites
- Cloudflare account (free tier)
- Node.js 18+
- Wrangler CLI: `npm install -g wrangler` then `wrangler login`

### 1 — Create KV namespaces

```bash
cd worker
wrangler kv namespace create "DOMAIN_CACHE"
wrangler kv namespace create "COMMUNITY_VOTES"
```

Copy both IDs into `worker/wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "DOMAIN_CACHE"
id = "YOUR_CACHE_ID"

[[kv_namespaces]]
binding = "COMMUNITY_VOTES"
id = "YOUR_VOTES_ID"
```

### 2 — Deploy the Worker

```bash
wrangler deploy
```

Copy the Worker URL from the output (e.g. `https://domain-authenticator.abc123.workers.dev`).

### 3 — Update the extension

Open `extension/background.js` and update line 7:

```js
const WORKER_URL = 'https://domain-authenticator.YOUR_ACTUAL_SUBDOMAIN.workers.dev';
```

### 4 — Load the extension in Chrome

1. Go to `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `extension/` folder

### 5 — Deploy the demo page

```bash
wrangler pages deploy docs/ --project-name=domain-authenticator-demo --branch=main
```

---

## Live demo

[domain-authenticator-demo.pages.dev](https://domain-authenticator-demo.pages.dev)

---

## Why this was built

Cloudflare One secures the network layer (Gateway) and device layer (WARP + DEX). The browser is the missing third layer — where 90%+ of enterprise work happens. This prototype demonstrates:

- **Browser-layer signals** that network-level inspection structurally cannot see (rendered DOM, digit substitution attacks, form action destinations)
- **Edge-native AI inference** via Workers AI — sub-100ms analysis at 300+ global PoPs
- **Community trust signals** as a feedback loop — one user's detection protects all users via KV global replication
- **Policy integration thesis** — trust score as a Gateway policy condition alongside device posture and identity

---

