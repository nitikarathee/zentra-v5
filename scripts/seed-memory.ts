/**
 * Load ~25 realistic past events into the Hindsight memory bank.
 * Run:  npm run seed:memory     (or: npx tsx scripts/seed-memory.ts)
 * Needs HINDSIGHT_BASE_URL, HINDSIGHT_API_KEY and HINDSIGHT_BANK_ID in .env
 */
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  const { isConfigured, getBankId } = await import('../server/hindsight.ts');
  const { seedMemory, SEED_EVENTS } = await import('../server/memory-seed.ts');

  if (!isConfigured()) {
    console.error('[seed] HINDSIGHT_BASE_URL is not set. Copy .env.example to .env and fill in the Hindsight values.');
    process.exit(1);
  }

  console.log(`[seed] Sending ${SEED_EVENTS.length} events to bank "${getBankId()}"...`);
  const res = await seedMemory();
  console.log(`[seed] Done. Stored ${res.stored}/${res.total}${res.failed ? `, ${res.failed} failed` : ''}.`);
  if (res.stored === 0) {
    console.error('[seed] Nothing was stored. Check your Hindsight URL / API key (see warnings above).');
    process.exit(1);
  }
  console.log('[seed] Hindsight processes memories asynchronously - give it ~30-60 seconds before you run the demo.');
  // let debounced journal write flush
  setTimeout(() => process.exit(0), 800);
}

main().catch((err) => {
  console.error('[seed] Failed:', err);
  process.exit(1);
});
