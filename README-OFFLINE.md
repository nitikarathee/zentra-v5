# Run ZENTRA fully offline

Why this is needed: the AI Studio link (remix-zentra.ai.studio) runs the server in Google's cloud.
With no internet your phone/laptop cannot reach that server, so you see "Ingestion Failed - Load failed".
That cannot be fixed inside the hosted link. The server must run on YOUR machine.

## One-time setup (needs internet once)
1. Install Node.js LTS from https://nodejs.org
2. Unzip this project.

## Every time (works with Wi-Fi OFF)
- Windows: double-click `start-offline.bat`
- Mac/Linux: `./start-offline.sh`

First run installs packages (internet once). After that it needs no internet at all.
Open http://localhost:3000

## Show it on your phone with no internet
Turn on a phone hotspot (or any Wi-Fi without internet), connect the laptop, run the script.
It prints a "Phone" address like http://192.168.x.x:3000. Open it on the phone.

## What runs offline
Config ingestion, vendor detection, normalization, the offline AI classifier (server/offline-ai.ts),
parser training, CIS/NIST/STIG/ISO evaluation, vendor CLI remediation templates, PDF reports.
Gemini is never called when ZENTRA_OFFLINE=true.

## Report seals, injection guard, dry-run fixes (added)
- Every PDF/ZIP is sealed with HMAC-SHA256 (key in `data/seal.key` or `ZENTRA_SEAL_SECRET`). Use **Verify Report** with the `.seal.json` file: edited content shows TAMPERED.
- Uploaded configs are regex-scanned for prompt injection before parsing/AI; hits are stripped, the device is flagged quarantined and logged in the audit ledger.
- Fix commands are editable (Edit / Reset / Approve) in a DRY RUN preview; nothing is ever executed. Each fix is badged Template or AI-generated (Gemini).
