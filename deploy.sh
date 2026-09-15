#!/bin/bash
set -e
echo "=== Domain Authenticator v2 — Deploy ==="

if ! command -v wrangler &> /dev/null; then echo "Install wrangler first: npm install -g wrangler"; exit 1; fi
wrangler whoami || { echo "Run 'wrangler login' first."; exit 1; }

cd worker

echo ""
echo "Creating KV namespaces..."
echo "--- Cache namespace ---"
wrangler kv namespace create "DOMAIN_CACHE" 2>&1 || true
echo ""
echo "--- Votes namespace ---"
wrangler kv namespace create "COMMUNITY_VOTES" 2>&1 || true

echo ""
echo ">>> Update worker/wrangler.toml with both KV namespace IDs from above <<<"
echo ">>> Then press Enter to continue..."
read

echo "Deploying Worker..."
DEPLOY_OUTPUT=$(wrangler deploy 2>&1)
echo "$DEPLOY_OUTPUT"

WORKER_URL=$(echo "$DEPLOY_OUTPUT" | grep -oP 'https://[a-zA-Z0-9.-]+\.workers\.dev' | head -1 || echo "")
if [ -z "$WORKER_URL" ]; then
  echo "Enter your Worker URL:"
  read -p "> " WORKER_URL
fi

cd ..

echo "Updating extension files..."
sed -i "s|https://domain-authenticator.YOUR_SUBDOMAIN.workers.dev|$WORKER_URL|g" extension/background.js
echo "Done! Worker: $WORKER_URL"
echo ""
echo "Next: chrome://extensions → Developer Mode → Load unpacked → select extension/"
