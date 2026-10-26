import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/* ==========================================================================
   REPORT SEALS  (HMAC-SHA256 over canonical JSON of the report contents)
   A plain hash can be recomputed by anyone who edits a report. An HMAC needs
   the server's secret key, so only this ZENTRA server can produce a valid seal.
   ========================================================================== */

const DATA_DIR = path.join(process.cwd(), 'data');
const KEY_FILE = path.join(DATA_DIR, 'seal.key');
const SEAL_STORE = path.join(DATA_DIR, 'report-seals.json');

let cachedSecret: string | null = null;

function getSecret(): string {
  if (cachedSecret) return cachedSecret;
  if (process.env.ZENTRA_SEAL_SECRET) {
    cachedSecret = process.env.ZENTRA_SEAL_SECRET;
    return cachedSecret;
  }
  try {
    if (fs.existsSync(KEY_FILE)) {
      cachedSecret = fs.readFileSync(KEY_FILE, 'utf-8').trim();
      if (cachedSecret) return cachedSecret;
    }
  } catch {
    // fall through and generate
  }
  cachedSecret = crypto.randomBytes(32).toString('hex');
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(KEY_FILE, cachedSecret, { encoding: 'utf-8', mode: 0o600 });
  } catch (err) {
    console.warn('Could not persist seal key; seals will not survive a restart:', err);
  }
  return cachedSecret;
}

// Stable JSON: object keys sorted recursively so the same content always hashes the same.
export function canonicalize(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

export function computeSeal(payload: any): string {
  return crypto.createHmac('sha256', getSecret()).update(canonicalize(payload)).digest('hex');
}

export function verifySeal(payload: any, seal: string): boolean {
  if (typeof seal !== 'string' || !/^[0-9a-f]{64}$/i.test(seal.trim())) return false;
  const expected = Buffer.from(computeSeal(payload), 'hex');
  const given = Buffer.from(seal.trim().toLowerCase(), 'hex');
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

export interface SealRecord {
  id: string;
  kind: string;
  label: string;
  seal: string;
  algorithm: 'HMAC-SHA256';
  sealedAt: string;
}

export function recordSeal(kind: string, label: string, seal: string, sealedAt: string): SealRecord {
  const rec: SealRecord = {
    id: `seal-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    kind,
    label,
    seal,
    algorithm: 'HMAC-SHA256',
    sealedAt,
  };
  try {
    let all: SealRecord[] = [];
    if (fs.existsSync(SEAL_STORE)) all = JSON.parse(fs.readFileSync(SEAL_STORE, 'utf-8'));
    all.unshift(rec);
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(SEAL_STORE, JSON.stringify(all.slice(0, 500), null, 2), 'utf-8');
  } catch (err) {
    console.warn('Could not store seal record:', err);
  }
  return rec;
}

/* ==========================================================================
   PROMPT-INJECTION GUARD (regex first, works fully offline)
   ========================================================================== */

const INJECTION_RULES: Array<{ regex: RegExp; pattern: string; risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' }> = [
  { regex: /\b(ignore|disregard|forget|override|bypass)\b[^\n]{0,30}\b(all|any|previous|prior|above|earlier|your|the)\b[^\n]{0,30}\b(instructions?|rules?|prompts?|guidelines?|policy|policies)\b/i, pattern: 'Instruction Override', risk: 'CRITICAL' },
  { regex: /\byou\s+are\s+now\b/i, pattern: 'Role Hijack ("you are now")', risk: 'HIGH' },
  { regex: /\b(act|behave|pretend)\s+as\s+(if\s+you\s+are\s+|a\s+|an\s+)/i, pattern: 'Persona Injection', risk: 'MEDIUM' },
  { regex: /\b(reveal|show|print|display|leak|repeat|output|dump)\b[^\n]{0,25}\b(system|hidden|initial|secret)\s+(prompt|instructions?|message)/i, pattern: 'System Prompt Extraction', risk: 'CRITICAL' },
  { regex: /\b(mark|set|report|flag|label|declare|treat)\b[^\n]{0,30}\b(device|config|configuration|switch|router|firewall|this)\b[^\n]{0,30}\b(as\s+)?(fully\s+)?(compliant|passed|secure|safe)\b/i, pattern: 'Verdict Manipulation', risk: 'CRITICAL' },
  { regex: /\b(set|force|give|assign)\b[^\n]{0,20}\b(compliance\s+)?score\b[^\n]{0,15}\b(to\s+)?100/i, pattern: 'Score Manipulation', risk: 'CRITICAL' },
  { regex: /\b(do\s+not|don't|never)\s+(report|flag|mention|list)\b[^\n]{0,40}\b(finding|violation|issue|fail)/i, pattern: 'Finding Suppression', risk: 'HIGH' },
  { regex: /(<\|im_start\|>|<\|system\|>|\[INST\]|<<SYS>>|^\s*[#!;/*\- ]*system\s*:)/i, pattern: 'Chat-Template / Role Marker', risk: 'HIGH' },
  { regex: /\b(jailbreak|DAN\s+mode|developer\s+mode|do\s+anything\s+now)\b/i, pattern: 'Jailbreak Keyword', risk: 'HIGH' },
];

export interface InjectionHit {
  line: number;
  pattern: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  excerpt: string;
}

export interface InjectionScanResult {
  flagged: boolean;
  hits: InjectionHit[];
  sanitized: string;
}

export function scanForInjection(text: string, filename = ''): InjectionScanResult {
  const lines = String(text).split(/\r?\n/);
  const hits: InjectionHit[] = [];
  const isJson = /\.json$/i.test(filename);

  const cleaned = lines.map((line, idx) => {
    for (const rule of INJECTION_RULES) {
      if (rule.regex.test(line)) {
        hits.push({
          line: idx + 1,
          pattern: rule.pattern,
          risk: rule.risk,
          excerpt: line.trim().slice(0, 140),
        });
        // JSON must stay parseable: neutralise only inside the string; other formats: drop the line.
        return isJson
          ? line.replace(/[^"\\]*(ignore|disregard|forget|override|bypass|you are now|reveal|mark|set|system)[^"\\]*/i, '[QUARANTINED]')
          : '! [ZENTRA QUARANTINED LINE REMOVED - prompt injection pattern]';
      }
    }
    return line;
  });

  return { flagged: hits.length > 0, hits, sanitized: cleaned.join('\n') };
}

// Check free-text fields (control titles, remediation hints) before they reach any AI call.
export function scanFields(fields: Array<string | undefined | null>): InjectionHit[] {
  const out: InjectionHit[] = [];
  fields.forEach((f, i) => {
    if (typeof f === 'string' && f.length) out.push(...scanForInjection(f).hits.map((h) => ({ ...h, line: i + 1 })));
  });
  return out;
}
