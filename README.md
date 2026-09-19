# Domain Authenticator

> AI-powered domain trust scoring for your browser

A Chrome extension that analyzes every domain you visit in real time, blocks dangerous sites before you interact with them, and shows a detailed trust breakdown — powered by AI running on the edge.

**Live demo → [domain-authenticator-demo.pages.dev](https://domain-authenticator-demo.pages.dev)**

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

## Try the live demo

Visit **[domain-authenticator-demo.pages.dev](https://domain-authenticator-demo.pages.dev)** to test the scoring engine directly in your browser — no installation needed. Try these:

| Domain | Expected result |
|---|---|
| `github.com` | Trusted — 98 |
| `g00gle.xyz` | Dangerous — blocked |
| `paypal-secure.top` | Dangerous — blocked |
| `micr0soft-login.buzz` | Dangerous — blocked |

---

## Install the extension

The backend is already deployed and running. You only need to load the extension into Chrome.

**1. Clone the repo**

```bash
git clone https://github.com/keertipc7/domain-authenticator.git
```

**2. Open Chrome extensions**

Go to `chrome://extensions` in your browser.

**3. Enable Developer mode**

Toggle **Developer mode** on — top right corner.

**4. Load the extension**

Click **Load unpacked** → select the `extension/` folder from the cloned repo.

**5. Browse normally**

The shield icon appears in your extensions. Navigate to any site - click the icon for the full analysis.

---

## How it works

```
Chrome Extension (Manifest V3)
       │
       ▼
Edge API (Cloudflare Worker)
  ├── Heuristic engine
  │     ├── Digit substitution detection  (g00gle → google)
  │     ├── Brand similarity / typosquatting
  │     ├── TLD risk classification
  │     ├── Shannon entropy scoring
  │     ├── Subdomain abuse detection
  │     └── Combo signal overrides
  │
  ├── AI — Llama 3.1 8B
  │     └── Semantic analysis + plain-English explanation
  │
  └── Edge cache + community votes
        ├── Verdict cache (6h TTL, global)
        └── Vote tallies per domain
```

---

## Scoring model

| Signal | Weight | What it catches |
|---|---|---|
| Brand similarity | 30% | Typosquatting, digit substitution, contains-brand patterns |
| AI verdict | 22% | Semantic patterns heuristics miss |
| TLD risk | 18% | High-abuse TLDs (.xyz, .top, .buzz and 30+ others) |
| Entropy | 10% | DGA-generated random-looking domains |
| Subdomain abuse | 10% | paypal.com.evil.xyz patterns |
| Special characters | 5% | Hyphen and digit abuse |
| Length | 5% | Unusually long domains |

**Combo overrides** short-circuit the weighted average. Digit substitution of a known brand (e.g. `g00gle.xyz`) or brand impersonation on a high-risk TLD immediately forces `trustScore < 5` and `action: block`.

### Verdict thresholds

| Trust score | Verdict | Action |
|---|---|---|
| 75–100 | Trusted | Allow |
| 58–74 | Likely safe | Allow |
| 42–57 | Caution | Warn |
| 22–41 | Suspicious | Block |
| 0–21 | Dangerous | Block |

---

## Community voting

Every user gets a persistent anonymous ID. Votes are stored globally and feed back into scoring for the domains which are not in the verified list of the extension:

- One vote per user per domain (vote can be changed)
- Votes are weighted by reviewer activity — active reviewers carry more weight, capped at 2×
- Minimum 2 votes before community signal activates
- Strong unsafe consensus (60%+ weighted): warn → block, allow → warn
- Strong safe consensus (60%+ weighted, 50%+ confidence): block → warn
- Voting busts the cache so the next analysis reflects the new verdict immediately

---

## Project structure

```
├── worker/
│   ├── src/index.js        # Edge API — full analysis engine
│   ├── wrangler.toml       # Worker config
│   └── package.json
├── extension/
│   ├── manifest.json       # Chrome Manifest V3
│   ├── background.js       # Service worker — navigation, badge, blocking
│   ├── content.js          # Block overlay + warning banner injection
│   ├── content.css         # Injected UI styles
│   ├── icons/
│   └── popup/
│       ├── popup.html      # Analysis dashboard
│       ├── popup.css
│       └── popup.js
└── docs/
    └── index.html          # Live demo page
```

---

## Built with

- Cloudflare Workers — edge API at 300+ global locations
- Cloudflare Workers AI — Llama 3.1 8B for semantic domain analysis
- Cloudflare Workers KV — global verdict cache and community votes
- Cloudflare Pages — demo page hosting

---

<details>
<summary>Deploy your own instance</summary>

### Prerequisites
- Cloudflare account (free tier)
- Node.js 18+
- `npm install -g wrangler` then `wrangler login`

### 1 — Create KV namespaces

```bash
cd worker
wrangler kv namespace create "DOMAIN_CACHE"
wrangler kv namespace create "COMMUNITY_VOTES"
```

Paste both IDs into `worker/wrangler.toml`.

### 2 — Deploy the Worker

```bash
wrangler deploy
```

### 3 — Update the extension

In `extension/background.js` line 7, replace the `WORKER_URL` with your deployed Worker URL.

### 4 — Deploy the demo page

```bash
wrangler pages deploy docs/ --project-name=domain-authenticator-demo --branch=main
```

</details>

---

*[domain-authenticator-demo.pages.dev](https://domain-authenticator-demo.pages.dev)*