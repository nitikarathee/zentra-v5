#!/usr/bin/env bash
# ZENTRA - fully offline launcher (macOS / Linux)
cd "$(dirname "$0")"
export ZENTRA_OFFLINE=true
unset GEMINI_API_KEY

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Install it once from https://nodejs.org (LTS), then run this again."; exit 1
fi
if [ ! -d node_modules ]; then
  echo "First run only: installing packages (needs internet ONE time)..."
  npm install || { echo "npm install failed (no internet?). Connect once and retry."; exit 1; }
fi
if [ ! -d dist ]; then
  echo "Building app..."; npm run build || exit 1
fi
export NODE_ENV=production
echo ""
echo "ZENTRA running OFFLINE (no cloud AI, no internet needed)"
echo "  Laptop : http://localhost:3000"
node -e "const n=require('os').networkInterfaces();for(const k in n)for(const i of n[k])if(i.family==='IPv4'&&!i.internal)console.log('  Phone  : http://'+i.address+':3000   (same Wi-Fi / hotspot, no internet needed)')"
echo ""
npx tsx server.ts
