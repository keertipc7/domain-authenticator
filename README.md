# Domain Authenticator

> AI-powered domain trust scoring — Chrome extension + Cloudflare Workers AI

A Chrome extension that analyzes every domain you visit in real time, blocks dangerous sites, and shows a detailed trust breakdown powered by Cloudflare Workers AI, Workers KV, and community voting.

Built as a working prototype for the **Product Manager, Browser Extension** role at Cloudflare.

---

## What it does

- **Auto-analyzes every site** — scores domains the moment you navigate using heuristics + AI
- **Blocks dangerous domains** — full-screen overlay with AI reasoning before you can proceed
- **Warns on suspicious sites** — amber banner with one-click dismiss
- **Detailed popup** — trust gauge, signal breakdown, AI explanation, community votes
- **Community voting** — mark sites as Safe / Suspicious / Unsafe; votes feed back into scoring
- **Right-click any link** — analyze before you click
- **Report AI mistakes** — helps improve accuracy over time

## Architecture

```
Chrome Extension (Manifest V3)
       │
       ▼
Cloudflare Worker (Edge API)
  ├── Heuristic engine (typosquatting, entropy, TLD risk, digit substitution)
  ├── Workers AI — Llama 3.1 8B (semantic analysis + plain-English explanation)
  └── Workers KV (verdict cache + community votes)
```

## Stack

| Layer | Technology |
|---|---|
| Browser extension | Chrome Manifest V3 |
| Edge compute | Cloudflare Workers |
| AI inference | Cloudflare Workers AI (Llama 3.1 8B) |
| Caching | Cloudflare Workers KV |
| Community data | Cloudflare Workers KV |
| Hosting (demo page) | Cloudflare Pages |

Everything runs on Cloudflare's **free tier**.

## Project structure

```
├── worker/
│   ├── src/index.js       # Cloudflare Worker — analysis engine
│   ├── wrangler.toml      # Worker config (add your KV IDs here)
│   └── package.json
├── extension/
│   ├── manifest.json      # Chrome Manifest V3
│   ├── background.js      # Service worker — auto-analyze, badge, blocking
│   ├── content.js         # Injected scripts — block overlay, warning banner
│   ├── content.css        # Styles for injected UI
│   ├── icons/
│   └── popup/
│       ├── popup.html
│       ├── popup.css
│       └── popup.js
└── docs/
    └── index.html         # Portfolio demo page (deployed to Cloudflare Pages)
```

## Deploy

### Prerequisites
- Cloudflare account (free)
- Node.js 18+
- `npm install -g wrangler` then `wrangler login`

### 1. Create KV namespaces

```bash
cd worker
wrangler kv namespace create "DOMAIN_CACHE"
wrangler kv namespace create "COMMUNITY_VOTES"
```

Copy both IDs into `worker/wrangler.toml`.

### 2. Deploy the Worker

```bash
wrangler deploy
```

Copy the Worker URL from the output.

### 3. Update the extension

Replace `YOUR_SUBDOMAIN` in `extension/background.js` with your Worker URL.

### 4. Load the extension in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

### 5. Deploy the demo page (optional)

```bash
wrangler pages deploy docs/ --project-name=domain-authenticator-demo --branch=main
```

## Demo

Live demo: [domain-authenticator-demo.pages.dev](https://domain-authenticator-demo.pages.dev)

## Why this exists

Cloudflare One today secures the network layer (Gateway) and device layer (WARP). The browser is the missing third layer — where 90%+ of enterprise work happens. This prototype demonstrates:

- Browser-layer signals that network-level DLP can't see
- Edge-native AI inference via Workers AI
- Community-powered trust signals as a feedback loop into Gateway threat intel
- The integration thesis: browser extension + Workers AI + KV + Gateway policy engine

See [docs/PRD.md](docs/PRD.md) for the full product analysis.
