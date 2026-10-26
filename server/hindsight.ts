/**
 * ZENTRA <-> Hindsight (by Vectorize) persistent agent memory.
 *
 * Design rules:
 *  - FAIL SOFT. Every function catches its own errors, logs a console.warn and
 *    returns an empty result, so ZENTRA keeps working when Hindsight is
 *    unreachable, not configured, or the npm package is missing.
 *  - NEVER SLOW THE APP. Every network call has a timeout. Writes are
 *    fire-and-forget (callers do not need to await them).
 *  - Runtime ON/OFF switch (`memoryEnabled`). OFF pauses BOTH reads and writes
 *    so the before/after demo is clean.
 */
import fs from 'fs';
import path from 'path';

export const MEMORY_MISSION =
  'Security compliance analyst memory for this organisation. Remember findings, risk decisions, remediation outcomes and vendor quirks.';

export interface RecalledMemory {
  id?: string;
  text: string;
  type?: string;
  date?: string | null;
}

export interface JournalEntry {
  id: string;
  at: string; // when the event happened (ISO)
  context: string;
  content: string;
  metadata: Record<string, string>;
  synced: boolean; // true once Hindsight accepted it
}

/* ------------------------------ configuration ------------------------------ */

const BASE_URL = () => (process.env.HINDSIGHT_BASE_URL || '').trim();
const API_KEY = () => (process.env.HINDSIGHT_API_KEY || '').trim();
export const getBankId = () => (process.env.HINDSIGHT_BANK_ID || 'zentra-security').trim();

export const isConfigured = () => Boolean(BASE_URL());

/** Live-binding flag. Change it with setMemoryEnabled(). */
export let memoryEnabled = true;
export function setMemoryEnabled(on: boolean) {
  memoryEnabled = Boolean(on);
}

let connected = false;
let lastError: string | null = null;
let client: any = null;
let clientPromise: Promise<any> | null = null;
let bankReady: Promise<void> | null = null;

function noteOk() {
  connected = true;
  lastError = null;
}
function noteFail(where: string, err: unknown) {
  connected = false;
  lastError = `${where}: ${err instanceof Error ? err.message : String(err)}`;
  console.warn(`[ZENTRA/Hindsight] ${lastError}`);
}

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      }
    );
  });
}

/** Lazily create the Hindsight client. Returns null when not configured / package missing. */
async function getClient(): Promise<any | null> {
  if (client) return client;
  if (!isConfigured()) return null;
  if (!clientPromise) {
    clientPromise = (async () => {
      try {
        const mod: any = await import('@vectorize-io/hindsight-client');
        const HindsightClient = mod.HindsightClient || mod.default?.HindsightClient || mod.default;
        const opts: Record<string, any> = { baseUrl: BASE_URL() };
        if (API_KEY()) opts.apiKey = API_KEY();
        client = new HindsightClient(opts);
        return client;
      } catch (err) {
        noteFail('client init (is @vectorize-io/hindsight-client installed? run npm install)', err);
        clientPromise = null;
        return null;
      }
    })();
  }
  return clientPromise;
}

/** Create the memory bank once. "Already exists" is not an error. */
export function initHindsight(): Promise<void> {
  if (!bankReady) {
    bankReady = (async () => {
      const c = await getClient();
      if (!c) {
        if (!isConfigured()) console.warn('[ZENTRA/Hindsight] HINDSIGHT_BASE_URL not set - memory layer idle (app works normally).');
        return;
      }
      try {
        await withTimeout(
          c.createBank(getBankId(), { name: getBankId(), mission: MEMORY_MISSION }),
          10000,
          'createBank'
        );
        noteOk();
        console.log(`[ZENTRA/Hindsight] Memory bank "${getBankId()}" ready.`);
      } catch (err: any) {
        const msg = String(err?.message || err);
        if (/exist|already|409|conflict/i.test(msg)) {
          noteOk();
          console.log(`[ZENTRA/Hindsight] Memory bank "${getBankId()}" already exists - reusing.`);
        } else {
          noteFail('createBank', err);
          bankReady = null; // allow a retry on the next call
        }
      }
    })();
  }
  return bankReady;
}

/* --------------------------- local activity journal --------------------------- */
// A small local log of everything ZENTRA sent to Hindsight. It powers the
// "recent memories" timeline and shows sync status. Recall still comes ONLY
// from Hindsight.

const JOURNAL_PATH = path.resolve(process.cwd(), 'data', 'memory-journal.json');
const JOURNAL_MAX = 500;
let journal: JournalEntry[] = [];
try {
  if (fs.existsSync(JOURNAL_PATH)) {
    const parsed = JSON.parse(fs.readFileSync(JOURNAL_PATH, 'utf8'));
    if (Array.isArray(parsed)) journal = parsed;
  }
} catch {
  journal = [];
}

let saveTimer: ReturnType<typeof setTimeout> | null = null;
function saveJournal() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      fs.writeFileSync(JOURNAL_PATH, JSON.stringify(journal.slice(0, JOURNAL_MAX), null, 2));
    } catch {
      /* read-only filesystem etc. - journal stays in memory */
    }
  }, 400);
}

// Skip identical content retained within the last 10 minutes (re-running an evaluation or
// re-opening a preview must not flood the memory bank with duplicates).
const recentlyRetained = new Map<string, number>();
const DEDUPE_MS = 10 * 60 * 1000;
function isDuplicate(content: string): boolean {
  const now = Date.now();
  for (const [k, t] of recentlyRetained) if (now - t > DEDUPE_MS) recentlyRetained.delete(k);
  if (recentlyRetained.has(content)) return true;
  recentlyRetained.set(content, now);
  return false;
}

function addJournal(entry: Omit<JournalEntry, 'id' | 'synced'> & { synced?: boolean }): JournalEntry {
  const e: JournalEntry = {
    id: `mem-${Date.now()}-${Math.floor(Math.random() * 100000)}`,
    synced: false,
    ...entry,
  };
  journal.unshift(e);
  if (journal.length > JOURNAL_MAX) journal.length = JOURNAL_MAX;
  saveJournal();
  return e;
}

export function recentMemories(limit = 50): JournalEntry[] {
  return journal.slice(0, limit);
}

/* --------------------------------- helpers --------------------------------- */

function stringifyMetadata(meta?: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  if (!meta) return out;
  for (const [k, v] of Object.entries(meta)) {
    if (v === undefined || v === null) continue;
    out[k] = typeof v === 'string' ? v : JSON.stringify(v);
  }
  return out;
}

function normalizeRecall(raw: any): RecalledMemory[] {
  const arr: any[] = Array.isArray(raw?.results) ? raw.results : Array.isArray(raw) ? raw : [];
  return arr
    .map((r) => ({
      id: r?.id,
      text: String(r?.text ?? r?.content ?? '').trim(),
      type: r?.type ?? r?.fact_type,
      date: r?.occurred_start ?? r?.occurredStart ?? r?.mentioned_at ?? r?.date ?? null,
    }))
    .filter((r) => r.text.length > 0);
}

/* ---------------------------------- retain ---------------------------------- */

/**
 * Store a memory. Fire-and-forget: safe to call without await.
 * Always resolves, never throws.
 */
export async function remember(
  content: string,
  context: string,
  metadata?: Record<string, unknown>,
  timestamp?: Date | string
): Promise<boolean> {
  if (!memoryEnabled || !content) return false;
  if (!timestamp && isDuplicate(content)) return false;
  const meta = stringifyMetadata(metadata);
  const entry = addJournal({
    at: timestamp ? new Date(timestamp).toISOString() : new Date().toISOString(),
    context,
    content,
    metadata: meta,
  });
  try {
    await initHindsight();
    const c = await getClient();
    if (!c) return false;
    const opts: Record<string, any> = { context, metadata: meta, async: true };
    if (timestamp) opts.timestamp = timestamp;
    await withTimeout(c.retain(getBankId(), content, opts), 15000, 'retain');
    entry.synced = true;
    saveJournal();
    noteOk();
    return true;
  } catch (err) {
    noteFail('retain', err);
    return false;
  }
}

/**
 * Bulk store. Respects the ON/OFF switch unless { force: true } (the seed script / "Load sample memory"
 * button use force so sample history can be loaded while Memory is toggled OFF for the demo).
 */
export async function rememberBatch(
  allItems: Array<{ content: string; context: string; metadata?: Record<string, unknown>; timestamp?: Date | string }>,
  opts: { force?: boolean } = {}
): Promise<{ stored: number; failed: number }> {
  if (!opts.force && !memoryEnabled) return { stored: 0, failed: 0 };
  const items = opts.force ? allItems : allItems.filter((i) => i.timestamp || !isDuplicate(i.content));
  if (items.length === 0) return { stored: 0, failed: 0 };
  let stored = 0;
  let failed = 0;
  try {
    await initHindsight();
    const c = await getClient();
    if (!c) return { stored: 0, failed: items.length };

    const payload = items.map((i) => ({
      content: i.content,
      context: i.context,
      metadata: stringifyMetadata(i.metadata),
      ...(i.timestamp ? { timestamp: i.timestamp } : {}),
    }));

    let batchOk = false;
    if (typeof c.retainBatch === 'function') {
      try {
        await withTimeout(c.retainBatch(getBankId(), payload, { async: true }), 60000, 'retainBatch');
        batchOk = true;
      } catch (err) {
        console.warn('[ZENTRA/Hindsight] retainBatch failed, falling back to one-by-one retain:', (err as Error)?.message);
      }
    }
    if (batchOk) {
      stored = items.length;
    } else {
      for (const p of payload) {
        try {
          await withTimeout(c.retain(getBankId(), p.content, { context: p.context, metadata: p.metadata, timestamp: (p as any).timestamp, async: true }), 20000, 'retain');
          stored++;
        } catch (err) {
          failed++;
          noteFail('retain (seed)', err);
        }
      }
    }
    if (stored > 0) noteOk();
  } catch (err) {
    noteFail('rememberBatch', err);
    return { stored, failed: items.length - stored };
  }
  for (const i of items) {
    addJournal({
      at: i.timestamp ? new Date(i.timestamp).toISOString() : new Date().toISOString(),
      context: i.context,
      content: i.content,
      metadata: stringifyMetadata(i.metadata),
      synced: stored > 0,
    });
  }
  return { stored, failed };
}

/* ---------------------------------- recall ---------------------------------- */

/** Search memory. Returns [] when disabled / unreachable. */
export async function recall(query: string): Promise<RecalledMemory[]> {
  if (!memoryEnabled || !query) return [];
  try {
    await initHindsight();
    const c = await getClient();
    if (!c) return [];
    const res = await withTimeout(c.recall(getBankId(), query, { budget: 'mid', maxTokens: 2048 }), 12000, 'recall');
    noteOk();
    return normalizeRecall(res);
  } catch (err) {
    noteFail('recall', err);
    return [];
  }
}

/** Ask Hindsight to reason over memory (audit-readiness briefing). Returns '' when unavailable. */
export async function brief(query: string, context?: string): Promise<string> {
  if (!memoryEnabled || !query) return '';
  try {
    await initHindsight();
    const c = await getClient();
    if (!c) return '';
    const res: any = await withTimeout(c.reflect(getBankId(), query, { budget: 'mid', context }), 45000, 'reflect');
    noteOk();
    return String(res?.text ?? res?.answer ?? '').trim();
  } catch (err) {
    noteFail('reflect', err);
    return '';
  }
}

/* ---------------------------------- status ---------------------------------- */

export function memoryStatus() {
  let host = '';
  try {
    host = BASE_URL() ? new URL(BASE_URL()).host : '';
  } catch {
    host = BASE_URL();
  }
  return {
    enabled: memoryEnabled,
    configured: isConfigured(),
    connected,
    bankId: getBankId(),
    host,
    lastError,
    journalCount: journal.length,
  };
}

/** Build a compact prompt section from recalled memories (used by gemini.ts and the template engine). */
export function formatMemoriesForPrompt(memories: RecalledMemory[], max = 8): string {
  return memories
    .slice(0, max)
    .map((m, i) => `${i + 1}. ${m.text.replace(/\s+/g, ' ').slice(0, 400)}`)
    .join('\n');
}
