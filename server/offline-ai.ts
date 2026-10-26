/**
 * ZENTRA OFFLINE AI ENGINE
 * ------------------------------------------------------------------
 * Runs with NO internet and NO API key. Used when:
 *   - ZENTRA_OFFLINE=true is set, or
 *   - GEMINI_API_KEY is missing, or
 *   - the Gemini call fails / times out.
 *
 * How it works (classic NLP, fully local):
 *   1. Tokenize each unrecognized config line (vendor words, punctuation and
 *      numbers are normalized, polarity words like "no/disable" are split off).
 *   2. Compare it to a knowledge base of canonical phrases for every security
 *      field using TF-IDF weighted cosine similarity.
 *   3. If the best match is similar enough, extract the value (true/false,
 *      number, version, IP list...) and tag it source = "offline".
 *   4. Separately, fingerprint the vendor from characteristic syntax.
 *
 * Self-contained on purpose: no imports, so it is easy to test and reuse.
 */

export type OfflineFieldKey =
  | 'telnet_enabled'
  | 'http_server_enabled'
  | 'https_enabled'
  | 'ssh_version'
  | 'ssh_timeout'
  | 'ssh_retries'
  | 'password_encryption'
  | 'min_password_length'
  | 'aaa_enabled'
  | 'logging_hosts'
  | 'ntp_servers'
  | 'snmp_version'
  | 'snmp_community_default'
  | 'banner_set'
  | 'session_timeout'
  | 'tls_min_version'
  | 'cdp_lldp_disabled'
  | 'source_routing_disabled'
  | 'service_tcp_keepalives';

export interface OfflineLineInput {
  lineNumber: number;
  line: string;
}

export interface OfflineFieldResult {
  field: OfflineFieldKey;
  value: boolean | number | string | string[];
  sourceLine: string;
  lineNumber: number;
  confidence: number; // 0..1
  similarity: number; // raw cosine similarity 0..1
}

export interface OfflineVendorGuess {
  vendor: string;
  confidence: number; // 0..100
  score: number;
}

// -----------------------------------------------------------------------------
// KNOWLEDGE BASE: canonical multi-vendor phrases per security field
// -----------------------------------------------------------------------------

const KNOWLEDGE: Record<OfflineFieldKey, string[]> = {
  telnet_enabled: [
    'transport input telnet',
    'telnet server',
    'service telnet',
    'set system services telnet',
    'telnet-server enable',
    'set admin-telnet',
    'ip telnet',
    'management telnet',
    'telnet access vty',
    'services telnet connection-limit',
  ],
  http_server_enabled: [
    'ip http server',
    'http server',
    'set system services web-management http',
    'set admin-http',
    'management http server',
    'http-server',
    'service www',
    'web interface http insecure',
    'admin-http',
  ],
  https_enabled: [
    'ip http secure-server',
    'https server',
    'web-management https',
    'set admin-https',
    'management https',
    'ssl web gui',
    'service www-ssl',
    'https-server',
    'admin-https',
  ],
  ssh_version: [
    'ip ssh version 2',
    'ssh protocol version',
    'set system services ssh protocol-version v2',
    'ssh version',
    'sshd protocol',
    'management ssh version',
    'ssh v1 compatibility',
    'ssh server version',
  ],
  ssh_timeout: [
    'ip ssh time-out',
    'ssh timeout',
    'ssh authentication timeout',
    'sshd login grace time',
    'ssh server timeout seconds',
    'admin-ssh timeout',
    'ssh idle timeout',
  ],
  ssh_retries: [
    'ip ssh authentication-retries',
    'ssh retries',
    'ssh max auth tries',
    'ssh authentication attempts',
    'sshd maxauthtries',
    'ssh login attempts',
  ],
  password_encryption: [
    'service password-encryption',
    'enable secret',
    'username secret password hash',
    'password hash sha512',
    'encrypt password',
    'password encryption type',
    'enable algorithm-type scrypt secret',
    'crypt hash sha256',
    'username privilege secret type 9',
    'username privilege secret',
    'password hashing algorithm',
  ],
  min_password_length: [
    'security passwords min-length',
    'password minimum length',
    'min password length',
    'set password-policy minimum-length',
    'password policy length',
    'set system login password minimum-length',
    'passwd min length',
    'password-length',
  ],
  aaa_enabled: [
    'aaa new-model',
    'aaa authentication login',
    'aaa authorization',
    'tacacs-server host',
    'radius-server host',
    'set system tacplus-server',
    'authentication-profile server radius',
    'aaa accounting',
    'tacacs server group',
    'set system authentication-order radius tacplus',
  ],
  logging_hosts: [
    'logging host',
    'logging server',
    'syslog server',
    'set system syslog host',
    'logging trap',
    'remote syslog destination',
    'set log syslog server',
    'logging source-interface',
    'syslog profile server',
    'logging remote',
  ],
  ntp_servers: [
    'ntp server',
    'ntp peer',
    'set system ntp server',
    'ntp authenticate',
    'time server',
    'set deviceconfig system ntp-servers',
    'sntp server',
    'ntp source',
  ],
  snmp_version: [
    'snmp-server group v3',
    'snmp version',
    'snmp v3 auth priv',
    'set snmp v3',
    'snmpv3 user authentication',
    'snmp-server user',
    'snmp engineid',
    'snmp-server version',
    'snmp v2c',
    'snmp agent version',
  ],
  snmp_community_default: [
    'snmp-server community public',
    'snmp community private',
    'set snmp community public',
    'snmp community string default',
    'snmp-server community ro rw',
    'community read-only authorization',
    'snmp community name',
  ],
  banner_set: [
    'banner motd',
    'banner login',
    'login banner',
    'set system login message',
    'pre-login banner',
    'banner exec',
    'set banner',
    'legal notice banner',
    'login-banner text',
    'set system login announcement',
  ],
  session_timeout: [
    'exec-timeout',
    'exec-timeout minutes seconds',
    'session timeout',
    'idle timeout',
    'inactivity timeout',
    'set system login idle-timeout',
    'management console timeout',
    'set admintimeout',
    'line vty exec-timeout',
    'console idle timeout',
    'auto logout',
    'session-timeout minutes',
  ],
  tls_min_version: [
    'ssl-server-cipher-suite tls',
    'tls minimum version',
    'ip http tls-version',
    'set ssl-tls-service-profile min-version',
    'ssl min proto version',
    'tls 1.2',
    'https tls version',
    'set ssl-min-proto-version tls1-2',
    'crypto tls protocol',
    'ssl protocol version',
  ],
  cdp_lldp_disabled: [
    'cdp run',
    'lldp run',
    'cdp enable',
    'lldp transmit',
    'set protocols lldp',
    'lldp receive',
    'discovery protocol cdp lldp',
    'set system lldp',
  ],
  source_routing_disabled: [
    'ip source-route',
    'source routing',
    'set ip-options source-route',
    'ip-source-route drop',
    'accept-source-route',
  ],
  service_tcp_keepalives: [
    'service tcp-keepalives-in',
    'tcp-keepalives out',
    'tcp keepalive',
    'set tcp-keepalive',
    'tcp keepalives-in service',
  ],
};

/** Fields whose semantic meaning is "feature is OFF" (polarity is inverted). */
const INVERTED_FIELDS = new Set<OfflineFieldKey>(['cdp_lldp_disabled', 'source_routing_disabled']);

const BOOL_FIELDS = new Set<OfflineFieldKey>([
  'telnet_enabled',
  'http_server_enabled',
  'https_enabled',
  'aaa_enabled',
  'banner_set',
  'cdp_lldp_disabled',
  'source_routing_disabled',
  'service_tcp_keepalives',
]);

// -----------------------------------------------------------------------------
// TOKENIZER + TF-IDF
// -----------------------------------------------------------------------------

const NEGATIVE_WORDS = new Set([
  'no', 'disable', 'disabled', 'off', 'false', 'deny', 'block', 'none',
  'remove', 'delete', 'undo', 'drop', 'reject',
]);
const POSITIVE_WORDS = new Set([
  'enable', 'enabled', 'on', 'true', 'yes', 'allow', 'permit', 'accept', 'active',
]);
const STOP_WORDS = new Set([
  'set', 'the', 'to', 'a', 'of', 'in', 'for', 'and', 'is', 'config', 'configure',
  'edit', 'commit', 'ip', 'service', 'system', 'input',
]);

function stripNoise(line: string): string {
  return line
    .toLowerCase()
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g, ' ') // IPv4
    .replace(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/g, ' ') // hostnames / FQDNs
    .replace(/["'`;{}]/g, ' ');
}

function tokenize(line: string): { topic: string[]; negative: boolean; positive: boolean } {
  const raw = stripNoise(line).split(/[^a-z0-9]+/).filter(Boolean);
  const topic: string[] = [];
  let negative = false;
  let positive = false;
  for (const t of raw) {
    if (NEGATIVE_WORDS.has(t)) { negative = true; continue; }
    if (POSITIVE_WORDS.has(t)) { positive = true; continue; }
    if (/^\d+$/.test(t)) continue;
    if (STOP_WORDS.has(t)) continue;
    if (t.length < 2) continue;
    topic.push(t);
  }
  return { topic, negative, positive };
}

type Vec = Map<string, number>;

interface Exemplar {
  field: OfflineFieldKey;
  text: string;
  vec: Vec;
  norm: number;
}

let EXEMPLARS: Exemplar[] | null = null;
let IDF: Map<string, number> = new Map();

function buildIndex(): Exemplar[] {
  if (EXEMPLARS) return EXEMPLARS;

  const docs: { field: OfflineFieldKey; text: string; tokens: string[] }[] = [];
  for (const [field, phrases] of Object.entries(KNOWLEDGE) as [OfflineFieldKey, string[]][]) {
    for (const text of phrases) {
      docs.push({ field, text, tokens: tokenize(text).topic });
    }
  }

  const df = new Map<string, number>();
  for (const d of docs) {
    for (const t of new Set(d.tokens)) df.set(t, (df.get(t) || 0) + 1);
  }
  const N = docs.length;
  IDF = new Map();
  for (const [t, n] of df) IDF.set(t, Math.log((N + 1) / (n + 0.5)) + 1);

  EXEMPLARS = docs.map((d) => {
    const vec = toVec(d.tokens);
    return { field: d.field, text: d.text, vec, norm: norm(vec) };
  });
  return EXEMPLARS;
}

function toVec(tokens: string[]): Vec {
  const tf = new Map<string, number>();
  for (const t of tokens) tf.set(t, (tf.get(t) || 0) + 1);
  const v: Vec = new Map();
  for (const [t, c] of tf) {
    const idf = IDF.get(t);
    // Unknown words get no weight: they cannot prove similarity.
    if (idf !== undefined) v.set(t, c * idf);
  }
  return v;
}

function norm(v: Vec): number {
  let s = 0;
  for (const x of v.values()) s += x * x;
  return Math.sqrt(s);
}

function cosine(a: Vec, an: number, b: Vec, bn: number): number {
  if (!an || !bn) return 0;
  let dot = 0;
  for (const [t, x] of a) {
    const y = b.get(t);
    if (y) dot += x * y;
  }
  return dot / (an * bn);
}

// -----------------------------------------------------------------------------
// VALUE EXTRACTION
// -----------------------------------------------------------------------------

const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const FQDN = /\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;

function numbersOf(line: string): number[] {
  const cleaned = line.replace(IPV4, ' ');
  return (cleaned.match(/\b\d+(?:\.\d+)?\b/g) || []).map(Number);
}

function extractValue(
  field: OfflineFieldKey,
  line: string,
  negative: boolean
): boolean | number | string | string[] | null {
  const lower = line.toLowerCase();

  if (BOOL_FIELDS.has(field)) {
    const on = !negative;
    return INVERTED_FIELDS.has(field) ? !on : on;
  }

  switch (field) {
    case 'ssh_version': {
      const m = lower.match(/(?:version|protocol-version|protocol|\bv)\s*[:=]?\s*([12])\b/) ||
                lower.match(/\bv([12])\b/);
      return m ? m[1] : null;
    }
    case 'snmp_version': {
      if (/v3|version\s*3|snmpv3/.test(lower)) return 'v3';
      if (/v2c|\b2c\b|version\s*2c/.test(lower)) return 'v2c';
      if (/\bv1\b|version\s*1\b/.test(lower)) return 'v1';
      return null;
    }
    case 'snmp_community_default': {
      return /community/.test(lower) && /\b(public|private)\b/.test(lower) && !negative ? true : null;
    }
    case 'tls_min_version': {
      const m = lower.match(/tls\s*v?\s*1[._-]?([0-3])/);
      if (m) return `TLS 1.${m[1]}`;
      if (/ssl\s*v?3/.test(lower)) return 'SSLv3';
      return null;
    }
    case 'password_encryption': {
      const t = lower.match(/\btype\s*([0-9])\b/) || lower.match(/\b(?:secret|password)\s+([0-9])\b/);
      if (t) return `Type ${t[1]}`;
      if (/sha-?512|\$6\$/.test(lower)) return 'SHA-512';
      if (/sha-?256|\$5\$/.test(lower)) return 'SHA-256';
      if (/scrypt/.test(lower)) return 'scrypt';
      if (/md5|\$1\$/.test(lower)) return 'MD5';
      if (/password-encryption/.test(lower)) return negative ? 'None' : 'Type 7';
      return null;
    }
    case 'min_password_length':
    case 'ssh_retries': {
      const n = numbersOf(line);
      return n.length ? n[n.length - 1] : null;
    }
    case 'ssh_timeout': {
      const n = numbersOf(line);
      return n.length ? n[0] : null;
    }
    case 'session_timeout': {
      const n = numbersOf(line);
      if (!n.length) return null;
      let minutes: number;
      if (/exec-timeout/.test(lower) && n.length >= 2) minutes = n[0] + n[1] / 60;
      else if (/\bsec(?:ond)?s?\b/.test(lower)) minutes = n[0] / 60;
      else if (/\bhours?\b/.test(lower)) minutes = n[0] * 60;
      else minutes = n[0];
      return Math.round(minutes * 10) / 10;
    }
    case 'logging_hosts':
    case 'ntp_servers': {
      const hosts = [...(line.match(IPV4) || []), ...(line.match(FQDN) || [])];
      return hosts.length ? Array.from(new Set(hosts)) : null;
    }
    default:
      return null;
  }
}

// -----------------------------------------------------------------------------
// PUBLIC: CLASSIFY LINES
// -----------------------------------------------------------------------------

export const OFFLINE_SIMILARITY_THRESHOLD = 0.5;

export function classifyLinesOffline(lines: OfflineLineInput[]): OfflineFieldResult[] {
  const index = buildIndex();
  const results: OfflineFieldResult[] = [];

  for (const { lineNumber, line } of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('!') || trimmed.startsWith('#') || trimmed.startsWith('//')) continue;
    // Free-text lines must never be classified (e.g. interface descriptions mentioning "banner").
    if (/^(?:description|remark|alias|comment|label|set description|set comment)\b/i.test(trimmed)) continue;

    const { topic, negative } = tokenize(trimmed);
    if (!topic.length) continue;
    const vec = toVec(topic);
    const n = norm(vec);

    let best: { field: OfflineFieldKey; sim: number } | null = null;
    for (const ex of index) {
      const sim = cosine(vec, n, ex.vec, ex.norm);
      if (!best || sim > best.sim) best = { field: ex.field, sim };
    }
    if (!best || best.sim < OFFLINE_SIMILARITY_THRESHOLD) continue;

    const value = extractValue(best.field, trimmed, negative || /^\s*(no|delete|undo)\s/i.test(trimmed));
    if (value === null) continue;

    results.push({
      field: best.field,
      value,
      sourceLine: trimmed,
      lineNumber,
      similarity: Math.round(best.sim * 100) / 100,
      confidence: Math.round(Math.min(0.88, 0.5 + best.sim * 0.4) * 100) / 100,
    });
  }
  return results;
}

// -----------------------------------------------------------------------------
// PUBLIC: VENDOR FINGERPRINT
// -----------------------------------------------------------------------------

const VENDOR_SIGNATURES: { vendor: string; patterns: [RegExp, number][] }[] = [
  {
    vendor: 'Cisco IOS-XE / IOS',
    patterns: [
      [/^\s*line vty\b/im, 3], [/^\s*enable secret\b/im, 3], [/^\s*service timestamps\b/im, 2],
      [/^\s*ip ssh version\b/im, 2], [/^\s*interface (?:gigabit|tengigabit|fastethernet)/im, 2], [/^\s*aaa new-model/im, 2],
    ],
  },
  {
    vendor: 'Cisco NX-OS',
    patterns: [[/^\s*feature (?:ssh|telnet|lacp|bgp)\b/im, 4], [/^\s*vpc domain\b/im, 3], [/^\s*interface ethernet\d+\/\d+/im, 2]],
  },
  {
    vendor: 'Cisco ASA',
    patterns: [[/^\s*nameif\b/im, 4], [/^\s*security-level\b/im, 4], [/^\s*access-group .* in interface/im, 3]],
  },
  {
    vendor: 'Juniper JunOS',
    patterns: [[/^\s*set (?:system|interfaces|security|protocols)\b/im, 3], [/^\s*(?:system|interfaces|security) \{/im, 3], [/host-name\s+\S+;/i, 2], [/\bpolicy-options\b/i, 2]],
  },
  {
    vendor: 'Arista EOS',
    patterns: [[/^\s*management api http-commands\b/im, 4], [/^\s*daemon\b/im, 2], [/^\s*spanning-tree mode mstp/im, 1], [/\barista\b/i, 4], [/^\s*interface ethernet\d+$/im, 1]],
  },
  {
    vendor: 'Fortinet FortiOS',
    patterns: [[/^\s*config system global\b/im, 5], [/^\s*config firewall policy\b/im, 4], [/^\s*end\s*$/im, 1], [/\bfortigate\b/i, 3]],
  },
  {
    vendor: 'Palo Alto PAN-OS',
    patterns: [[/set deviceconfig system\b/i, 5], [/set (?:rulebase|zone|network) /i, 3], [/\bpan-os\b|\bpanorama\b/i, 3]],
  },
  {
    vendor: 'Huawei VRP',
    patterns: [[/^\s*sysname\b/im, 4], [/^\s*undo\b/im, 3], [/^\s*user-interface vty\b/im, 4], [/^\s*return\s*$/im, 1]],
  },
  {
    vendor: 'Mikrotik RouterOS',
    patterns: [[/^\s*\/(?:ip|system|interface)\b/im, 4], [/\bnumbers?=/i, 2], [/\bname=\S+/i, 1]],
  },
  {
    vendor: 'SONiC Open Networking NOS',
    patterns: [[/"DEVICE_METADATA"|"PORT"\s*:|config_db/i, 5], [/\bsonic\b/i, 4], [/\bFEATURE\b.*\bstate\b/i, 1]],
  },
  {
    vendor: 'VyOS / EdgeOS',
    patterns: [[/^\s*set (?:service|firewall|interfaces) .*['"]/im, 2], [/\bvyos\b/i, 5], [/^\s*set system host-name '/im, 3]],
  },
];

export function guessVendorOffline(config: string, filename = ''): OfflineVendorGuess | null {
  const text = `${filename}\n${config}`;
  const scored = VENDOR_SIGNATURES.map(({ vendor, patterns }) => {
    let score = 0;
    for (const [re, w] of patterns) if (re.test(text)) score += w;
    return { vendor, score };
  }).sort((a, b) => b.score - a.score);

  const top = scored[0];
  if (!top || top.score < 3) return null;
  const runnerUp = scored[1]?.score ?? 0;
  const margin = top.score - runnerUp;
  const confidence = Math.max(55, Math.min(90, 55 + margin * 5 + top.score));
  return { vendor: top.vendor, confidence, score: top.score };
}
