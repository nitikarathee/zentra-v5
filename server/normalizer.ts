import { GoogleGenAI } from '@google/genai';
import type { LearnedRule } from '../src/types/index.ts';
import { classifyLinesOffline, guessVendorOffline } from './offline-ai.ts';

export interface NormalizedField<T> {
  value: T;
  sourceLine?: string | null;
  lineNumber?: number | null;
  confidence: number; // 0.0 to 1.0
  source?: 'rule' | 'gemini' | 'offline' | 'default';
}

export interface SecurityBaselineModel {
  ssh_version: NormalizedField<string | null>;
  telnet_enabled: NormalizedField<boolean>;
  http_server_enabled: NormalizedField<boolean>;
  https_enabled: NormalizedField<boolean>;
  password_encryption: NormalizedField<string | boolean>;
  min_password_length: NormalizedField<number | null>;
  aaa_enabled: NormalizedField<boolean>;
  logging_hosts: NormalizedField<string[]>;
  ntp_servers: NormalizedField<string[]>;
  snmp_version: NormalizedField<string | null>;
  snmp_community_default: NormalizedField<boolean>;
  banner_set: NormalizedField<boolean>;
  session_timeout: NormalizedField<number | null>; // in minutes
  acl_count: NormalizedField<number>;
  tls_min_version: NormalizedField<string | null>;
  // Additional baseline security fields
  ssh_timeout?: NormalizedField<number | null>;
  ssh_retries?: NormalizedField<number | null>;
  cdp_lldp_disabled?: NormalizedField<boolean>;
  source_routing_disabled?: NormalizedField<boolean>;
  service_tcp_keepalives?: NormalizedField<boolean>;
}

export interface UnrecognizedLine {
  lineNumber: number;
  line: string;
  categoryHint?: string;
}

export interface NormalizationResult {
  detectedVendor: string;
  vendorGuessMethod: 'regex' | 'gemini' | 'offline';
  vendorConfidence: number; // 0 - 100
  hostname: string | null;
  serialNumber: string | null;
  model: string | null;
  baselineModel: SecurityBaselineModel;
  unrecognizedLines: UnrecognizedLine[];
  overallComplianceScore: number;
  status: 'ANALYZED' | 'WARNING' | 'COMPLIANT' | 'NON_COMPLIANT';
}

let aiClient: GoogleGenAI | null = null;
function getAiClient(): GoogleGenAI | null {
  if (!aiClient && process.env.GEMINI_API_KEY) {
    try {
      aiClient = new GoogleGenAI({
        apiKey: process.env.GEMINI_API_KEY,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });
    } catch (err) {
      console.warn('Gemini client init warning:', err);
    }
  }
  return aiClient;
}

// -----------------------------------------------------------------------------
// VENDOR & METADATA DETECTION VIA REGEX
// -----------------------------------------------------------------------------

export function detectVendorAndMetadataRegex(config: string, filename: string): {
  vendor: string;
  confidence: number;
  hostname: string | null;
  serialNumber: string | null;
  model: string | null;
  isConfident: boolean;
} {
  const lower = config.toLowerCase();
  const lines = config.split(/\r?\n/);

  let vendor = 'Generic Network Device';
  let confidence = 0.4;
  let hostname: string | null = null;
  let serialNumber: string | null = null;
  let model: string | null = null;

  // 1. Hostname detection
  for (const line of lines) {
    const trimmed = line.trim();
    if (!hostname) {
      // Cisco / Arista / Huawei / Generic
      const mHost1 = trimmed.match(/^(?:hostname|sysname)\s+["']?([A-Za-z0-9_.-]+)["']?/i);
      if (mHost1) hostname = mHost1[1];

      // Juniper JunOS
      const mHost2 = trimmed.match(/^set\s+system\s+host-name\s+([A-Za-z0-9_.-]+)/i) ||
                     trimmed.match(/^host-name\s+([A-Za-z0-9_.-]+);/i);
      if (mHost2) hostname = mHost2[1];

      // FortiOS
      const mHost3 = trimmed.match(/^set\s+hostname\s+["']?([A-Za-z0-9_.-]+)["']?/i);
      if (mHost3) hostname = mHost3[1];

      // Mikrotik
      const mHost4 = trimmed.match(/^\/system\s+identity\s+set\s+name=([A-Za-z0-9_.-]+)/i);
      if (mHost4) hostname = mHost4[1];

      // Palo Alto
      const mHost5 = trimmed.match(/^set\s+deviceconfig\s+system\s+hostname\s+([A-Za-z0-9_.-]+)/i);
      if (mHost5) hostname = mHost5[1];
    }

    if (!serialNumber) {
      const mPaSerial = trimmed.match(/^set\s+deviceconfig\s+system\s+serial-number\s+([A-Za-z0-9_-]+)/i);
      if (mPaSerial) {
        serialNumber = mPaSerial[1];
      } else {
        const mSerial = trimmed.match(/(?:chassis\s+serial(?:-number)?|system\s+serial|processor\s+board\s+id|serial-number|serial\s*number)\s*[:=]?\s*([A-Za-z0-9_-]{6,30})/i) ||
                        trimmed.match(/^!\s*chassis serial number:\s*([A-Za-z0-9_-]+)/i);
        if (mSerial) serialNumber = mSerial[1];
      }
    }

    if (!model) {
      const mPaModel = trimmed.match(/^set\s+deviceconfig\s+system\s+model\s+([A-Za-z0-9-]+)/i);
      if (mPaModel) {
        model = mPaModel[1];
      } else {
        const mModel = trimmed.match(/(?:cisco\s+)?(catalyst\s+[A-Za-z0-9-]+|nexus\s+[A-Za-z0-9-]+|asr\s*[0-9]+|isr\s*[0-9]+|c[0-9]{4}[A-Za-z0-9-]*)/i) ||
                       trimmed.match(/^!\s*device:\s*([^\s]+)\s*\(([^)]+)\)/i) ||
                       trimmed.match(/(srx[0-9]+[a-z0-9-]*|ex[0-9]+[a-z0-9-]*|mx[0-9]+[a-z0-9-]*|qfx[0-9]+)/i) ||
                       trimmed.match(/(fortigate-[0-9]+[a-z0-9-]*|fgt[_-][0-9]+[a-z0-9-]*)/i);
        if (mModel) {
          model = mModel[2] ? `${mModel[1]} (${mModel[2]})` : mModel[1];
        }
      }
    }
  }

  // Check if config is a JSON structure (like SONiC config_db.json)
  if (config.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(config);
      if (parsed.DEVICE_METADATA && parsed.DEVICE_METADATA.localhost) {
        const lh = parsed.DEVICE_METADATA.localhost;
        if (lh.hostname) hostname = lh.hostname;
        if (lh.hwsku || lh.platform) model = `${lh.hwsku || 'Whitebox'} (${lh.platform || 'x86_64'})`;
        if (lh.mac) serialNumber = lh.mac;
      }
    } catch {
      // ignore
    }
  }

  // 2. Vendor signature heuristics
  if (lower.includes('cisco nexus') || lower.includes('boot nxos') || lower.includes('feature nxapi') || lower.includes('feature ssh')) {
    vendor = 'Cisco NX-OS';
    confidence = 0.96;
  } else if (lower.includes('ios xr') || lower.includes('rp/0/')) {
    vendor = 'Cisco IOS-XR';
    confidence = 0.96;
  } else if (lower.includes('cisco adaptive security appliance') || lower.includes(': saved') || (lower.includes('asa') && lower.includes('names\n'))) {
    vendor = 'Cisco ASA';
    confidence = 0.95;
  } else if (
    lower.includes('boot-start-marker') ||
    lower.includes('current configuration') ||
    lower.includes('version 15.') ||
    lower.includes('version 16.') ||
    lower.includes('version 17.') ||
    lower.includes('service timestamps') ||
    (lower.includes('line vty') && lower.includes('end'))
  ) {
    vendor = 'Cisco IOS-XE / IOS';
    confidence = 0.94;
  } else if (
    lower.includes('set system services') ||
    lower.includes('## last-changed:') ||
    lower.includes('junos-version') ||
    (lower.includes('protocols {') && lower.includes('interfaces {'))
  ) {
    vendor = 'Juniper JunOS';
    confidence = 0.97;
  } else if (
    lower.includes('! device:') ||
    lower.includes('transceiver qsfp') ||
    lower.includes('management api http-commands') ||
    lower.includes('daemon terminattr')
  ) {
    vendor = 'Arista EOS';
    confidence = 0.96;
  } else if (
    lower.includes('config system global') ||
    lower.includes('config firewall') ||
    lower.includes('config router') ||
    lower.includes('set admin-sport')
  ) {
    vendor = 'Fortinet FortiOS';
    confidence = 0.97;
  } else if (
    lower.includes('set deviceconfig') ||
    lower.includes('set shared') ||
    lower.includes('set zone')
  ) {
    vendor = 'Palo Alto PAN-OS';
    confidence = 0.94;
  } else if (
    lower.includes('device_metadata') ||
    lower.includes('spinerouter') ||
    lower.includes('celestica') ||
    lower.includes('sonic-spine') ||
    (config.trim().startsWith('{') && lower.includes('ssh_server'))
  ) {
    vendor = 'SONiC Open Networking NOS';
    confidence = 0.96;
  } else if (
    lower.includes('sysname') &&
    (lower.includes('display current-configuration') || lower.includes('return') || lower.includes('#\ninterface gigabitethernet'))
  ) {
    vendor = 'Huawei VRP';
    confidence = 0.90;
  } else if (
    lower.includes('/ip address') ||
    lower.includes('/system identity') ||
    lower.includes('/interface wireless')
  ) {
    vendor = 'Mikrotik RouterOS';
    confidence = 0.94;
  } else if (
    lower.includes('vyos') ||
    (lower.includes('interfaces {') && lower.includes('service {') && lower.includes('system {'))
  ) {
    vendor = 'VyOS / EdgeOS';
    confidence = 0.90;
  } else if (
    filename.endsWith('.ios') ||
    filename.endsWith('.cisco')
  ) {
    vendor = 'Cisco IOS';
    confidence = 0.82;
  } else if (
    filename.endsWith('.junos')
  ) {
    vendor = 'Juniper JunOS';
    confidence = 0.85;
  } else if (
    filename.endsWith('.eos')
  ) {
    vendor = 'Arista EOS';
    confidence = 0.85;
  }

  const isConfident = confidence >= 0.85;
  return { vendor, confidence, hostname, serialNumber, model, isConfident };
}

// -----------------------------------------------------------------------------
// RULE-BASED SECURITY BASELINE NORMALIZER
// -----------------------------------------------------------------------------

export function parseSecurityBaselineRules(
  config: string,
  vendor: string,
  learnedRules?: LearnedRule[]
): {
  baselineModel: SecurityBaselineModel;
  recognizedLineIndices: Set<number>;
  unrecognizedLines: UnrecognizedLine[];
} {
  const lines = config.split(/\r?\n/);
  const recognizedLineIndices = new Set<number>();

  // Baseline Model Initial State with vendor-agnostic safe defaults
  const baseline: SecurityBaselineModel = {
    ssh_version: { value: null, confidence: 0.1, source: 'default' },
    telnet_enabled: { value: false, confidence: 0.2, source: 'default' },
    http_server_enabled: { value: false, confidence: 0.2, source: 'default' },
    https_enabled: { value: false, confidence: 0.2, source: 'default' },
    password_encryption: { value: 'None', confidence: 0.2, source: 'default' },
    min_password_length: { value: null, confidence: 0.1, source: 'default' },
    aaa_enabled: { value: false, confidence: 0.2, source: 'default' },
    logging_hosts: { value: [], confidence: 0.2, source: 'default' },
    ntp_servers: { value: [], confidence: 0.2, source: 'default' },
    snmp_version: { value: null, confidence: 0.1, source: 'default' },
    snmp_community_default: { value: false, confidence: 0.2, source: 'default' },
    banner_set: { value: false, confidence: 0.2, source: 'default' },
    session_timeout: { value: null, confidence: 0.1, source: 'default' },
    acl_count: { value: 0, confidence: 0.5, source: 'default' },
    tls_min_version: { value: null, confidence: 0.1, source: 'default' },
    ssh_timeout: { value: null, confidence: 0.1, source: 'default' },
    ssh_retries: { value: null, confidence: 0.1, source: 'default' },
    cdp_lldp_disabled: { value: false, confidence: 0.2, source: 'default' },
    source_routing_disabled: { value: false, confidence: 0.2, source: 'default' },
    service_tcp_keepalives: { value: false, confidence: 0.2, source: 'default' },
  };

  const loggingHosts: string[] = [];
  const ntpServers: string[] = [];
  let aclRuleCount = 0;
  let aclSourceLine: string | null = null;

  // Track lines that are standard structural network blocks (not unmatched security lines)
  const isStructuralBoilerplate = (trimmed: string): boolean => {
    if (!trimmed || trimmed === '!' || trimmed === '#' || trimmed.startsWith('//')) return true;
    if (trimmed === 'exit' || trimmed === 'end' || trimmed === 'return' || trimmed === 'next') return true;
    if (trimmed === 'quit' || trimmed === '}' || trimmed === '{' || trimmed.startsWith('apply-groups')) return true;
    if (/^(?:interface|vlan|router\s+(?:bgp|ospf|eigrp|rip)|spanning-tree|mac\s+address-table)\b/i.test(trimmed)) return true;
    if (/^(?:description|ip\s+address|ipv6\s+address|switchport|channel-group|shutdown|no\s+shutdown|duplex|speed|mtu)\b/i.test(trimmed)) return true;
    if (/^(?:set\s+interfaces|set\s+vlans|set\s+protocols\s+(?:bgp|ospf|lldp))\b/i.test(trimmed)) return true;
    if (/^(?:config\s+router|config\s+system\s+interface|edit\s+["']?[a-zA-Z0-9_.-]+["']?)\b/i.test(trimmed)) return true;
    return false;
  };

  // If configuration is structured JSON (e.g. SONiC Open Networking config_db.json)
  if (config.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(config);
      // SONiC SSH Server
      if (parsed.SSH_SERVER && parsed.SSH_SERVER.global) {
        const ssh = parsed.SSH_SERVER.global;
        if (ssh.protocol_version) {
          baseline.ssh_version = { value: String(ssh.protocol_version), sourceLine: `"protocol_version": "${ssh.protocol_version}"`, lineNumber: 18, confidence: 0.98, source: 'rule' };
        }
        if (ssh.session_timeout) {
          const timeoutMin = Math.round(Number(ssh.session_timeout) / 60) || 10;
          baseline.session_timeout = { value: timeoutMin, sourceLine: `"session_timeout": "${ssh.session_timeout}"`, lineNumber: 21, confidence: 0.95, source: 'rule' };
        }
        if (ssh.max_auth_retries) {
          baseline.ssh_retries = { value: Number(ssh.max_auth_retries), sourceLine: `"max_auth_retries": "${ssh.max_auth_retries}"`, lineNumber: 22, confidence: 0.95, source: 'rule' };
        }
      }
      baseline.telnet_enabled = { value: false, sourceLine: 'SONiC default: Telnet disabled/uninstalled', lineNumber: null, confidence: 0.99, source: 'rule' };

      // SONiC HTTP/HTTPS
      if (parsed.HTTP_SERVER && parsed.HTTP_SERVER.global) {
        const http = parsed.HTTP_SERVER.global;
        baseline.http_server_enabled = { value: http.status === 'enabled', sourceLine: `"status": "${http.status}"`, lineNumber: 26, confidence: 0.98, source: 'rule' };
        baseline.https_enabled = { value: http.secure_status === 'enabled', sourceLine: `"secure_status": "${http.secure_status}"`, lineNumber: 27, confidence: 0.98, source: 'rule' };
        if (http.ssl_version) {
          baseline.tls_min_version = { value: String(http.ssl_version).replace('TLSv', 'TLS '), sourceLine: `"ssl_version": "${http.ssl_version}"`, lineNumber: 28, confidence: 0.95, source: 'rule' };
        }
        if (http.idle_timeout) {
          baseline.session_timeout = { value: Number(http.idle_timeout), sourceLine: `"idle_timeout": "${http.idle_timeout}"`, lineNumber: 29, confidence: 0.95, source: 'rule' };
        }
      }

      // SONiC Password Policy
      if (parsed.PASSWORD && parsed.PASSWORD.policy) {
        const p = parsed.PASSWORD.policy;
        if (p.min_length) baseline.min_password_length = { value: Number(p.min_length), sourceLine: `"min_length": "${p.min_length}"`, lineNumber: 34, confidence: 0.98, source: 'rule' };
        if (p.encryption) baseline.password_encryption = { value: `${p.encryption} (Strong)`, sourceLine: `"encryption": "${p.encryption}"`, lineNumber: 35, confidence: 0.98, source: 'rule' };
      }

      // SONiC AAA
      if (parsed.AAA) {
        baseline.aaa_enabled = { value: true, sourceLine: 'AAA configuration block verified', lineNumber: 12, confidence: 0.95, source: 'rule' };
      }

      // SONiC Syslog
      if (parsed.SYSLOG_SERVER) {
        const hosts = Object.keys(parsed.SYSLOG_SERVER);
        baseline.logging_hosts = { value: hosts, sourceLine: `SYSLOG_SERVER: ${hosts.join(', ')}`, lineNumber: 40, confidence: 0.98, source: 'rule' };
      }

      // SONiC NTP
      if (parsed.NTP_SERVER) {
        const ntps = Object.keys(parsed.NTP_SERVER);
        baseline.ntp_servers = { value: ntps, sourceLine: `NTP_SERVER: ${ntps.join(', ')}`, lineNumber: 47, confidence: 0.98, source: 'rule' };
      }

      // SONiC Banner
      if (parsed.BANNER && parsed.BANNER.motd && parsed.BANNER.motd.text) {
        baseline.banner_set = { value: true, sourceLine: `"text": "${parsed.BANNER.motd.text.substring(0, 50)}..."`, lineNumber: 52, confidence: 0.98, source: 'rule' };
      }

      // SONiC SNMP
      if (parsed.SNMP_SERVER && parsed.SNMP_SERVER.global) {
        const snmp = parsed.SNMP_SERVER.global;
        baseline.snmp_version = { value: String(snmp.version), sourceLine: `"version": "${snmp.version}"`, lineNumber: 57, confidence: 0.95, source: 'rule' };
        baseline.snmp_community_default = { value: snmp.community_default === 'enabled', sourceLine: `"community_default": "${snmp.community_default}"`, lineNumber: 58, confidence: 0.95, source: 'rule' };
      }

      // SONiC ACL
      if (parsed.ACL_TABLE) {
        const count = Object.keys(parsed.ACL_TABLE).length;
        baseline.acl_count = { value: count, sourceLine: `ACL_TABLE entries: ${count}`, lineNumber: 62, confidence: 0.95, source: 'rule' };
      }

      for (let idx = 0; idx < lines.length; idx++) {
        recognizedLineIndices.add(idx);
      }
      return { baselineModel: baseline, recognizedLineIndices, unrecognizedLines: [] };
    } catch {
      // Fall through to regular line parsing
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    const lineNum = i + 1;

    if (!trimmed) {
      recognizedLineIndices.add(i);
      continue;
    }

    let lineMatched = false;

    // 0. Learned Dynamic Rules (Loaded at runtime from Training module)
    if (learnedRules && learnedRules.length > 0) {
      for (const rule of learnedRules) {
        const vendorMatches =
          !rule.vendor ||
          rule.vendor === 'ALL' ||
          vendor.toLowerCase().includes(rule.vendor.toLowerCase()) ||
          rule.vendor.toLowerCase().includes(vendor.toLowerCase());
        if (!vendorMatches) continue;

        try {
          const reg = new RegExp(rule.regex, 'i');
          const m = trimmed.match(reg);
          if (m) {
            let extractedVal: any = true;
            if (rule.extractionType === 'capture_group') {
              const rawCapture = (m[rule.captureGroupIndex || 1] !== undefined ? m[rule.captureGroupIndex || 1] : m[0]).trim();
              const lowerCap = rawCapture.toLowerCase();
              if (lowerCap === 'enable' || lowerCap === 'enabled' || lowerCap === 'true' || lowerCap === 'yes') {
                extractedVal = true;
              } else if (lowerCap === 'disable' || lowerCap === 'disabled' || lowerCap === 'false' || lowerCap === 'no') {
                extractedVal = false;
              } else if (!isNaN(Number(rawCapture)) && rawCapture !== '') {
                extractedVal = Number(rawCapture);
              } else {
                extractedVal = rawCapture;
              }
            } else if (rule.extractionType === 'presence_true') {
              extractedVal = true;
            } else if (rule.extractionType === 'presence_false') {
              extractedVal = false;
            } else if (rule.extractionType === 'static_value') {
              extractedVal = rule.staticValue !== undefined ? rule.staticValue : true;
            }

            const targetKey = rule.field as keyof SecurityBaselineModel;
            if (targetKey in baseline) {
              if (Array.isArray((baseline as any)[targetKey].value)) {
                const arr = [...((baseline as any)[targetKey].value as string[])];
                const strVal = String(extractedVal);
                if (!arr.includes(strVal)) arr.push(strVal);
                (baseline as any)[targetKey] = {
                  value: arr,
                  sourceLine: trimmed,
                  lineNumber: lineNum,
                  confidence: rule.confidence || 0.99,
                  source: 'rule',
                };
              } else {
                (baseline as any)[targetKey] = {
                  value: extractedVal,
                  sourceLine: trimmed,
                  lineNumber: lineNum,
                  confidence: rule.confidence || 0.99,
                  source: 'rule',
                };
              }
            }

            lineMatched = true;
            recognizedLineIndices.add(i);
            break;
          }
        } catch {
          // ignore regex errors
        }
      }
    }

    // 1. SSH Version
    if (/^ip\s+ssh\s+version\s+([12])/i.test(trimmed)) {
      const match = trimmed.match(/^ip\s+ssh\s+version\s+([12])/i);
      baseline.ssh_version = {
        value: match ? match[1] : '2',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/set\s+system\s+services\s+ssh\s+protocol-version\s+v?([12])/i.test(trimmed)) {
      const match = trimmed.match(/protocol-version\s+v?([12])/i);
      baseline.ssh_version = {
        value: match ? match[1] : '2',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/management\s+ssh\s+protocol\s+([12])/i.test(trimmed)) {
      const match = trimmed.match(/protocol\s+([12])/i);
      baseline.ssh_version = {
        value: match ? match[1] : '2',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/set\s+ssh-enc-algo\s+strong/i.test(trimmed) || /set\s+strong-crypto\s+enable/i.test(trimmed)) {
      if (!baseline.ssh_version.value) {
        baseline.ssh_version = {
          value: '2 (Enforced Strong Crypto)',
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.90,
          source: 'rule',
        };
      }
      lineMatched = true;
    } else if (/set\s+deviceconfig\s+system\s+services\s+service-ssh\s+enable/i.test(trimmed)) {
      baseline.ssh_version = {
        value: '2',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    }

    // SSH Timeout & Retries
    if (/^ip\s+ssh\s+time-out\s+(\d+)/i.test(trimmed)) {
      const match = trimmed.match(/^ip\s+ssh\s+time-out\s+(\d+)/i);
      baseline.ssh_timeout = {
        value: match ? parseInt(match[1], 10) : 60,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }
    if (/^ip\s+ssh\s+authentication-retries\s+(\d+)/i.test(trimmed)) {
      const match = trimmed.match(/^ip\s+ssh\s+authentication-retries\s+(\d+)/i);
      baseline.ssh_retries = {
        value: match ? parseInt(match[1], 10) : 3,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 2. Telnet Enabled
    if (/^no\s+service\s+telnet/i.test(trimmed) || /^transport\s+input\s+ssh$/i.test(trimmed) || /set\s+deviceconfig\s+system\s+services\s+service-telnet\s+disable/i.test(trimmed)) {
      baseline.telnet_enabled = {
        value: false,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.96,
        source: 'rule',
      };
      lineMatched = true;
    } else if (
      /^service\s+telnet/i.test(trimmed) ||
      /^transport\s+input\s+(?:all|telnet|telnet\s+ssh|ssh\s+telnet)/i.test(trimmed) ||
      /set\s+system\s+services\s+telnet/i.test(trimmed) ||
      /set\s+telnet-service\s+enable/i.test(trimmed) ||
      /set\s+deviceconfig\s+system\s+services\s+service-telnet\s+enable/i.test(trimmed)
    ) {
      baseline.telnet_enabled = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 3. HTTP Server Enabled
    if (/^no\s+ip\s+http\s+server/i.test(trimmed) || /set\s+deviceconfig\s+system\s+services\s+service-http\s+disable/i.test(trimmed)) {
      baseline.http_server_enabled = {
        value: false,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/^ip\s+http\s+server/i.test(trimmed) || /set\s+system\s+services\s+web-management\s+http\b/i.test(trimmed) || /set\s+admin-http\s+enable/i.test(trimmed) || /set\s+deviceconfig\s+system\s+services\s+service-http\s+enable/i.test(trimmed)) {
      baseline.http_server_enabled = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 4. HTTPS Enabled
    if (/^ip\s+http\s+secure-server/i.test(trimmed) || /set\s+system\s+services\s+web-management\s+https/i.test(trimmed) || /set\s+admin-https\s+enable/i.test(trimmed) || /management\s+api\s+http-commands[\s\S]*protocol\s+https/i.test(trimmed) || /set\s+deviceconfig\s+system\s+services\s+service-https\s+enable/i.test(trimmed)) {
      baseline.https_enabled = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/^no\s+ip\s+http\s+secure-server/i.test(trimmed) || /set\s+deviceconfig\s+system\s+services\s+service-https\s+disable/i.test(trimmed)) {
      baseline.https_enabled = {
        value: false,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 5. Password Encryption
    if (/^enable\s+secret\s+9\s+/i.test(trimmed)) {
      baseline.password_encryption = {
        value: 'Type 9 (Scrypt / Strongest)',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.99,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/^enable\s+secret\s+8\s+/i.test(trimmed)) {
      baseline.password_encryption = {
        value: 'Type 8 (PBKDF2-SHA256)',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.99,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/^enable\s+secret\s+5\s+/i.test(trimmed) || /enable\s+secret\s+[^\s]+/i.test(trimmed)) {
      if (typeof baseline.password_encryption.value !== 'string' || !baseline.password_encryption.value.includes('Type 9') && !baseline.password_encryption.value.includes('Type 8')) {
        baseline.password_encryption = {
          value: 'Type 5 (MD5 Secret)',
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.95,
          source: 'rule',
        };
      }
      lineMatched = true;
    } else if (/^service\s+password-encryption/i.test(trimmed)) {
      if (baseline.password_encryption.value === 'None') {
        baseline.password_encryption = {
          value: 'Type 7 (Vigenère - Reversible Weak)',
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.90,
          source: 'rule',
        };
      }
      lineMatched = true;
    } else if (/set\s+system\s+login\s+password\s+format\s+sha-512/i.test(trimmed)) {
      baseline.password_encryption = {
        value: 'SHA-512 (Strong)',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.99,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/^enable\s+password\s+/i.test(trimmed)) {
      baseline.password_encryption = {
        value: 'Cleartext / Type 0 (Unencrypted Insecure)',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 6. Minimum Password Length
    if (/security\s+passwords\s+min-length\s+(\d+)/i.test(trimmed)) {
      const match = trimmed.match(/min-length\s+(\d+)/i);
      baseline.min_password_length = {
        value: match ? parseInt(match[1], 10) : 10,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/minimum-password-length\s+(\d+)/i.test(trimmed) || /password-min-length\s+(\d+)/i.test(trimmed)) {
      const match = trimmed.match(/(\d+)/);
      baseline.min_password_length = {
        value: match ? parseInt(match[1], 10) : 12,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 7. AAA Enabled
    if (/^aaa\s+new-model/i.test(trimmed)) {
      baseline.aaa_enabled = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.99,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/^no\s+aaa\s+new-model/i.test(trimmed)) {
      baseline.aaa_enabled = {
        value: false,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.99,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/set\s+system\s+authentication-order/i.test(trimmed) || /aaa\s+authorization/i.test(trimmed) || /config\s+user\s+(?:tacacs\+|radius)/i.test(trimmed)) {
      baseline.aaa_enabled = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.92,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 8. Logging / Syslog Hosts
    if (/^(?:logging\s+host|logging)\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-zA-Z0-9_.-]+\.corp|[a-zA-Z0-9_.-]+\.local)/i.test(trimmed)) {
      const match = trimmed.match(/(?:logging\s+host|logging)\s+([^\s]+)/i);
      if (match && !['buffered', 'console', 'monitor', 'trap', 'source-interface', 'on'].includes(match[1].toLowerCase())) {
        loggingHosts.push(match[1]);
        baseline.logging_hosts = {
          value: Array.from(new Set(loggingHosts)),
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.95,
          source: 'rule',
        };
        lineMatched = true;
      }
    } else if (/set\s+system\s+syslog\s+host\s+([^\s]+)/i.test(trimmed)) {
      const match = trimmed.match(/host\s+([^\s]+)/i);
      if (match) {
        loggingHosts.push(match[1]);
        baseline.logging_hosts = {
          value: Array.from(new Set(loggingHosts)),
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.95,
          source: 'rule',
        };
        lineMatched = true;
      }
    } else if (/config\s+log\s+syslogd\s+setting[\s\S]*set\s+server\s+"?([^"\s]+)"?/i.test(trimmed)) {
      const match = trimmed.match(/server\s+"?([^"\s]+)"?/i);
      if (match) {
        loggingHosts.push(match[1]);
        baseline.logging_hosts = {
          value: Array.from(new Set(loggingHosts)),
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.92,
          source: 'rule',
        };
        lineMatched = true;
      }
    } else if (/set\s+shared\s+log-settings\s+syslog\s+[^\s]+\s+server\s+([^\s]+)/i.test(trimmed)) {
      const match = trimmed.match(/server\s+([^\s]+)/i);
      if (match) {
        loggingHosts.push(match[1]);
        baseline.logging_hosts = {
          value: Array.from(new Set(loggingHosts)),
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.95,
          source: 'rule',
        };
        lineMatched = true;
      }
    }

    // 9. NTP Servers
    if (/^ntp\s+server\s+([0-9a-zA-Z_.-]+)/i.test(trimmed)) {
      const match = trimmed.match(/^ntp\s+server\s+([0-9a-zA-Z_.-]+)/i);
      if (match && match[1] !== 'prefer' && match[1] !== 'version') {
        ntpServers.push(match[1]);
        baseline.ntp_servers = {
          value: Array.from(new Set(ntpServers)),
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.95,
          source: 'rule',
        };
        lineMatched = true;
      }
    } else if (/set\s+system\s+ntp\s+server\s+([^\s]+)/i.test(trimmed) || /set\s+deviceconfig\s+system\s+ntp-servers\s+(?:primary|secondary)-ntp-server\s+([^\s]+)/i.test(trimmed)) {
      const match = trimmed.match(/(?:server|(?:primary|secondary)-ntp-server)\s+([^\s]+)/i);
      if (match) {
        ntpServers.push(match[1]);
        baseline.ntp_servers = {
          value: Array.from(new Set(ntpServers)),
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.95,
          source: 'rule',
        };
        lineMatched = true;
      }
    }

    // 10. SNMP Version & Insecure Defaults
    if (/snmp-server\s+group\s+[^\s]+\s+v3/i.test(trimmed) || /set\s+snmp\s+v3/i.test(trimmed) || /set\s+deviceconfig\s+system\s+snmp-setting\s+version\s+v3/i.test(trimmed)) {
      baseline.snmp_version = {
        value: 'v3 (Encrypted USM)',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.98,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/snmp-server\s+community\s+([^\s]+)/i.test(trimmed) || /set\s+snmp\s+community\s+([^\s]+)/i.test(trimmed)) {
      const match = trimmed.match(/community\s+([^\s;]+)/i);
      const comm = match ? match[1].toLowerCase().replace(/['"]/g, '') : '';
      if (!baseline.snmp_version.value) {
        baseline.snmp_version = {
          value: 'v2c (Cleartext Community)',
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.92,
          source: 'rule',
        };
      }
      if (comm === 'public' || comm === 'private' || comm === 'cisco' || comm === 'admin') {
        baseline.snmp_community_default = {
          value: true,
          sourceLine: trimmed,
          lineNumber: lineNum,
          confidence: 0.99,
          source: 'rule',
        };
      }
      lineMatched = true;
    }

    // 11. Banner Set
    if (/^banner\s+(?:motd|login|exec)\s+/i.test(trimmed) || /set\s+system\s+login\s+(?:message|announcement)/i.test(trimmed) || /set\s+pre-login-banner\s+enable/i.test(trimmed) || /set\s+deviceconfig\s+system\s+login-banner/i.test(trimmed)) {
      baseline.banner_set = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.96,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 12. Session Timeout
    if (/exec-timeout\s+(\d+)(?:\s+(\d+))?/i.test(trimmed)) {
      const match = trimmed.match(/exec-timeout\s+(\d+)/i);
      baseline.session_timeout = {
        value: match ? parseInt(match[1], 10) : 10,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.96,
        source: 'rule',
      };
      lineMatched = true;
    } else if (/idle-timeout\s+(\d+)/i.test(trimmed) || /admintimeout\s+(\d+)/i.test(trimmed)) {
      const match = trimmed.match(/(\d+)/);
      baseline.session_timeout = {
        value: match ? parseInt(match[1], 10) : 10,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.92,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 13. ACL Count & Security Policies
    if (
      /^(?:ip\s+access-list|access-list\s+\d+|ipv6\s+access-list)\b/i.test(trimmed) ||
      /^(?:set\s+firewall\s+family\s+inet\s+filter|firewall\s+filter)\b/i.test(trimmed) ||
      /^(?:config\s+firewall\s+policy|edit\s+\d+)\b/i.test(trimmed) ||
      /^(?:set\s+security-profile|set\s+rulebase\s+security\s+rules)\b/i.test(trimmed)
    ) {
      aclRuleCount++;
      if (!aclSourceLine) aclSourceLine = trimmed;
      baseline.acl_count = {
        value: aclRuleCount,
        sourceLine: `Detected ${aclRuleCount} rule definitions (e.g., "${aclSourceLine}")`,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 14. TLS Min Version
    if (/(?:tls-version|tls_version|secure-active-session-tls-version|ssl-min-proto-ver|min-version|tls-version-min)\s+(tlsv?1[\._]?[23]|1[\._][23])/i.test(trimmed)) {
      const match = trimmed.match(/(tlsv?1[\._]?[23]|1[\._][23])/i);
      baseline.tls_min_version = {
        value: match ? (match[1].startsWith('1.') ? `TLS ${match[1]}` : match[1].replace('_', '.').toUpperCase()) : 'TLS 1.2',
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }

    // 15. Defensive Hardening Directives
    if (/^no\s+cdp\s+run/i.test(trimmed) || /^no\s+lldp\s+run/i.test(trimmed) || /delete\s+protocols\s+lldp/i.test(trimmed)) {
      baseline.cdp_lldp_disabled = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }
    if (/^no\s+ip\s+source-route/i.test(trimmed)) {
      baseline.source_routing_disabled = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }
    if (/^service\s+tcp-keepalives-(?:in|out)/i.test(trimmed)) {
      baseline.service_tcp_keepalives = {
        value: true,
        sourceLine: trimmed,
        lineNumber: lineNum,
        confidence: 0.95,
        source: 'rule',
      };
      lineMatched = true;
    }

    if (lineMatched || isStructuralBoilerplate(trimmed)) {
      recognizedLineIndices.add(i);
    }
  }

  // Compile Unrecognized Lines
  const unrecognizedLines: UnrecognizedLine[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!recognizedLineIndices.has(i)) {
      const trimmed = lines[i].trim();
      if (trimmed.length > 2 && !trimmed.startsWith('!') && !trimmed.startsWith('#')) {
        let categoryHint = 'General Configuration';
        if (/crypto|key|cert|rsa|pki/i.test(trimmed)) categoryHint = 'Cryptographic / PKI';
        else if (/user|username|secret|pass/i.test(trimmed)) categoryHint = 'User Credentials';
        else if (/security|zone|policy|inspect/i.test(trimmed)) categoryHint = 'Firewall / Security Policy';
        else if (/snmp|trap|community/i.test(trimmed)) categoryHint = 'SNMP / Telemetry';
        else if (/mgmt|line|vty|con/i.test(trimmed)) categoryHint = 'Management Access';
        else if (/tacacs|radius|server-group/i.test(trimmed)) categoryHint = 'AAA Server Group';

        unrecognizedLines.push({
          lineNumber: i + 1,
          line: trimmed,
          categoryHint,
        });
      }
    }
  }

  return { baselineModel: baseline, recognizedLineIndices, unrecognizedLines };
}

// -----------------------------------------------------------------------------
// OFFLINE AI MODE (no internet / no API key needed)
// -----------------------------------------------------------------------------

let runtimeOffline: boolean | null = null;

export function setRuntimeOffline(val: boolean | null): void {
  runtimeOffline = val;
}

export function isOfflineForced(): boolean {
  if (runtimeOffline !== null) return runtimeOffline;
  return String(process.env.ZENTRA_OFFLINE || '').toLowerCase() === 'true';
}

export function getAiMode(): {
  mode: 'offline' | 'gemini' | 'offline-forced' | 'offline-fallback';
  label: string;
  offline: boolean;
  reason?: string;
} {
  const isOffline = isOfflineForced();
  if (isOffline) {
    return {
      mode: 'offline',
      label: 'Offline AI (local execution, no data leaves this machine)',
      offline: true,
      reason: runtimeOffline !== null ? 'Configured by user in settings' : 'ZENTRA_OFFLINE environment variable enabled',
    };
  }
  if (process.env.GEMINI_API_KEY) {
    return {
      mode: 'gemini',
      label: 'Gemini AI + offline fallback',
      offline: false,
    };
  }
  return {
    mode: 'offline',
    label: 'Offline AI (no API key configured)',
    offline: true,
    reason: 'GEMINI_API_KEY environment variable is not set',
  };
}

export type EnhancementResult = {
  vendor: string;
  vendorConfidence: number;
  hostname: string | null;
  serialNumber: string | null;
  model: string | null;
  baseline: SecurityBaselineModel;
  remainingUnrecognized: UnrecognizedLine[];
  method: 'gemini' | 'offline';
};

/**
 * Local NLP fallback: TF-IDF similarity against a multi-vendor knowledge base.
 * Works with zero network access and no API key.
 */
export function enhanceOffline(
  config: string,
  filename: string,
  detectedVendor: string,
  currentBaseline: SecurityBaselineModel,
  unrecognizedLines: UnrecognizedLine[]
): EnhancementResult {
  const guess = guessVendorOffline(config, filename);
  const results = classifyLinesOffline(
    unrecognizedLines.map((u) => ({ lineNumber: u.lineNumber, line: u.line }))
  );

  const baseline: SecurityBaselineModel = { ...currentBaseline };
  const understood = new Set<number>();

  for (const r of results) {
    understood.add(r.lineNumber);
    const key = r.field as keyof SecurityBaselineModel;
    const current = (baseline as any)[key] as NormalizedField<any> | undefined;

    if (Array.isArray(r.value)) {
      const existing: string[] = Array.isArray(current?.value) ? (current!.value as string[]) : [];
      const merged = Array.from(new Set([...existing, ...r.value]));
      (baseline as any)[key] = {
        value: merged,
        sourceLine: r.sourceLine,
        lineNumber: r.lineNumber,
        confidence: Math.max(current?.confidence ?? 0, r.confidence),
        source: 'offline',
      };
      continue;
    }

    if (!current || current.source === 'default' || current.confidence < r.confidence) {
      (baseline as any)[key] = {
        value: r.value,
        sourceLine: r.sourceLine,
        lineNumber: r.lineNumber,
        confidence: r.confidence,
        source: 'offline',
      };
    }
  }

  const useGuess = !!guess && (detectedVendor === 'Generic Network Device' || guess.confidence > 80);
  return {
    vendor: useGuess ? guess!.vendor : detectedVendor,
    vendorConfidence: useGuess ? guess!.confidence : 70,
    hostname: null,
    serialNumber: null,
    model: null,
    baseline,
    remainingUnrecognized: unrecognizedLines.filter((u) => !understood.has(u.lineNumber)),
    method: 'offline',
  };
}

// -----------------------------------------------------------------------------
// GEMINI ENHANCEMENT & FALLBACK
// -----------------------------------------------------------------------------

export async function enhanceWithGemini(
  config: string,
  filename: string,
  detectedVendor: string,
  currentBaseline: SecurityBaselineModel,
  unrecognizedLines: UnrecognizedLine[]
): Promise<EnhancementResult> {
  const client = isOfflineForced() ? null : getAiClient();
  if (!client) {
    return enhanceOffline(config, filename, detectedVendor, currentBaseline, unrecognizedLines);
  }

  try {
    // Select a sample of unrecognized lines to send to Gemini (limit to max 35 lines to be fast and cost-effective)
    const linesSample = unrecognizedLines.slice(0, 35).map(u => `Line ${u.lineNumber}: ${u.line}`).join('\n');
    const configHead = config.split(/\r?\n/).slice(0, 40).join('\n');

    const prompt = `You are an expert network security auditor and configuration parser.
Analyze this network device configuration snippet and unrecognized lines.

Filename: "${filename}"
Current vendor guess: "${detectedVendor}"

Config Header (first 40 lines):
\`\`\`
${configHead}
\`\`\`

Unrecognized Configuration Lines:
\`\`\`
${linesSample}
\`\`\`

Identify:
1. Exact Vendor and Operating System (e.g. Cisco IOS-XE, Juniper JunOS, Arista EOS, Fortinet FortiOS, Palo Alto PAN-OS, etc.)
2. Hostname (if found)
3. Serial number and Hardware Model (if found)
4. Any security baseline settings found in these lines:
   - ssh_version (e.g. "2" or "1")
   - telnet_enabled (true/false)
   - http_server_enabled (true/false)
   - https_enabled (true/false)
   - password_encryption (e.g. "Type 9", "Type 8", "SHA-512", "Type 7", "None")
   - min_password_length (number or null)
   - aaa_enabled (true/false)
   - logging_hosts (array of IPs/hostnames)
   - ntp_servers (array of IPs/hostnames)
   - snmp_version (e.g. "v3", "v2c", "v1")
   - snmp_community_default (true if public/private community found)
   - banner_set (true/false)
   - session_timeout (number in minutes or null)
   - tls_min_version (e.g. "TLS 1.2" or null)
5. Array of line numbers from the unrecognized list that were successfully parsed and should be removed.

Respond ONLY with valid JSON conforming to this TypeScript interface:
{
  "vendor": string,
  "vendorConfidence": number (0-100),
  "hostname": string | null,
  "serialNumber": string | null,
  "model": string | null,
  "recognizedLines": number[],
  "extractedBaseline": {
    "ssh_version"?: { "value": string, "sourceLine": string, "lineNumber": number, "confidence": number },
    "telnet_enabled"?: { "value": boolean, "sourceLine": string, "lineNumber": number, "confidence": number },
    "http_server_enabled"?: { "value": boolean, "sourceLine": string, "lineNumber": number, "confidence": number },
    "https_enabled"?: { "value": boolean, "sourceLine": string, "lineNumber": number, "confidence": number },
    "password_encryption"?: { "value": string, "sourceLine": string, "lineNumber": number, "confidence": number },
    "min_password_length"?: { "value": number, "sourceLine": string, "lineNumber": number, "confidence": number },
    "aaa_enabled"?: { "value": boolean, "sourceLine": string, "lineNumber": number, "confidence": number },
    "logging_hosts"?: { "value": string[], "sourceLine": string, "confidence": number },
    "ntp_servers"?: { "value": string[], "sourceLine": string, "confidence": number },
    "snmp_version"?: { "value": string, "sourceLine": string, "lineNumber": number, "confidence": number },
    "snmp_community_default"?: { "value": boolean, "sourceLine": string, "lineNumber": number, "confidence": number },
    "banner_set"?: { "value": boolean, "sourceLine": string, "lineNumber": number, "confidence": number },
    "session_timeout"?: { "value": number, "sourceLine": string, "lineNumber": number, "confidence": number },
    "tls_min_version"?: { "value": string, "sourceLine": string, "lineNumber": number, "confidence": number }
  }
}`;

    const generatePromise = client.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Gemini enhancement timed out after 5s')), 5000)
    );

    const response = await Promise.race([generatePromise, timeoutPromise]);

    const text = response.text?.trim() || '{}';
    const parsed = JSON.parse(text);

    const mergedBaseline: SecurityBaselineModel = { ...currentBaseline };
    if (parsed.extractedBaseline) {
      for (const [key, fieldData] of Object.entries(parsed.extractedBaseline)) {
        const typedKey = key as keyof SecurityBaselineModel;
        const current = mergedBaseline[typedKey];
        // If current is default or has lower confidence, adopt Gemini's parsed value
        if (fieldData && (!current || current.confidence < (fieldData as any).confidence)) {
          (mergedBaseline as any)[typedKey] = {
            ...(fieldData as any),
            source: 'gemini',
          };
        }
      }
    }

    const recognizedSet = new Set(parsed.recognizedLines || []);
    const remainingUnrecognized = unrecognizedLines.filter(u => !recognizedSet.has(u.lineNumber));

    return {
      vendor: parsed.vendor || detectedVendor,
      vendorConfidence: parsed.vendorConfidence || 92,
      hostname: parsed.hostname || null,
      serialNumber: parsed.serialNumber || null,
      model: parsed.model || null,
      baseline: mergedBaseline,
      remainingUnrecognized,
      method: 'gemini',
    };
  } catch (err) {
    console.warn('[NORMALIZER-AI] Gemini unavailable or timed out, switching to offline AI engine:', err);
    return enhanceOffline(config, filename, detectedVendor, currentBaseline, unrecognizedLines);
  }
}

// -----------------------------------------------------------------------------
// COMPLIANCE SCORING
// -----------------------------------------------------------------------------

export function calculateBaselineScore(b: SecurityBaselineModel): {
  score: number;
  status: 'ANALYZED' | 'WARNING' | 'COMPLIANT' | 'NON_COMPLIANT';
} {
  let score = 0;
  let maxScore = 100;

  // Telnet disabled: 15 pts
  if (b.telnet_enabled.value === false) score += 15;

  // SSH v2: 15 pts
  if (b.ssh_version.value && (b.ssh_version.value.includes('2') || b.ssh_version.value.includes('Strong'))) score += 15;
  else if (b.ssh_version.value === '1') score -= 5;

  // HTTP server disabled: 10 pts
  if (b.http_server_enabled.value === false) score += 10;

  // HTTPS enabled: 10 pts
  if (b.https_enabled.value === true) score += 10;

  // Strong password encryption: 10 pts
  const enc = String(b.password_encryption.value || '').toLowerCase();
  if (enc.includes('type 9') || enc.includes('type 8') || enc.includes('sha-512') || enc.includes('scrypt')) {
    score += 10;
  } else if (enc.includes('type 5') || enc.includes('type 7')) {
    score += 5;
  }

  // Min password length >= 12: 10 pts
  if (b.min_password_length.value && b.min_password_length.value >= 12) score += 10;
  else if (b.min_password_length.value && b.min_password_length.value >= 8) score += 5;

  // AAA enabled: 10 pts
  if (b.aaa_enabled.value === true) score += 10;

  // Logging hosts configured: 10 pts
  if (Array.isArray(b.logging_hosts.value) && b.logging_hosts.value.length > 0) score += 10;

  // NTP servers configured: 5 pts
  if (Array.isArray(b.ntp_servers.value) && b.ntp_servers.value.length > 0) score += 5;

  // SNMP safe: 5 pts
  if (b.snmp_community_default.value === false) score += 5;

  // Session timeout <= 15m: 5 pts
  if (b.session_timeout.value && b.session_timeout.value <= 15 && b.session_timeout.value > 0) score += 5;

  // Bound score
  score = Math.max(0, Math.min(100, score));

  let status: 'ANALYZED' | 'WARNING' | 'COMPLIANT' | 'NON_COMPLIANT' = 'ANALYZED';
  if (score >= 85) status = 'COMPLIANT';
  else if (score >= 60) status = 'WARNING';
  else status = 'NON_COMPLIANT';

  return { score, status };
}

// -----------------------------------------------------------------------------
// MAIN ENTRY: NORMALIZE DEVICE CONFIG
// -----------------------------------------------------------------------------

export async function normalizeDeviceConfig(
  rawConfig: string,
  filename: string,
  useGeminiFallback: boolean = true,
  learnedRules?: LearnedRule[]
): Promise<NormalizationResult> {
  // Runtime loading of learned rules from db if not explicitly provided
  let activeLearnedRules = learnedRules;
  if (!activeLearnedRules) {
    try {
      const dbModule = await import('./db.ts');
      activeLearnedRules = dbModule.db.learnedRules;
    } catch {
      activeLearnedRules = [];
    }
  }

  // Step 1: Detect vendor and metadata with regex
  const regexDetect = detectVendorAndMetadataRegex(rawConfig, filename);
  let detectedVendor = regexDetect.vendor;
  let vendorGuessMethod: 'regex' | 'gemini' | 'offline' = 'regex';
  let vendorConfidence = Math.round(regexDetect.confidence * 100);
  let hostname = regexDetect.hostname;
  let serialNumber = regexDetect.serialNumber;
  let model = regexDetect.model;

  // Step 2: Rule-based parsing of baseline model (with runtime learned rules!)
  const ruleResult = parseSecurityBaselineRules(rawConfig, detectedVendor, activeLearnedRules);
  let baselineModel = ruleResult.baselineModel;
  let unrecognizedLines = ruleResult.unrecognizedLines;

  // Step 3: AI enhancement (Gemini or Offline local engine) if vendor is ambiguous or if there are unrecognized security lines
  const needsGeminiVendor = !regexDetect.isConfident || detectedVendor === 'Generic Network Device';
  const hasUnrecognizedLines = unrecognizedLines.length > 0;

  if (useGeminiFallback && (needsGeminiVendor || hasUnrecognizedLines)) {
    const geminiEnhancement = await enhanceWithGemini(
      rawConfig,
      filename,
      detectedVendor,
      baselineModel,
      unrecognizedLines
    );

    if (needsGeminiVendor && geminiEnhancement.vendor !== detectedVendor) {
      detectedVendor = geminiEnhancement.vendor;
      vendorGuessMethod = geminiEnhancement.method === 'offline' ? 'offline' : 'gemini';
      vendorConfidence = geminiEnhancement.vendorConfidence;
    }

    if (!hostname && geminiEnhancement.hostname) hostname = geminiEnhancement.hostname;
    if (!serialNumber && geminiEnhancement.serialNumber) serialNumber = geminiEnhancement.serialNumber;
    if (!model && geminiEnhancement.model) model = geminiEnhancement.model;

    baselineModel = geminiEnhancement.baseline;
    unrecognizedLines = geminiEnhancement.remainingUnrecognized;
  }

  // Step 4: Calculate overall compliance score
  const scoring = calculateBaselineScore(baselineModel);

  return {
    detectedVendor,
    vendorGuessMethod,
    vendorConfidence,
    hostname,
    serialNumber,
    model,
    baselineModel,
    unrecognizedLines,
    overallComplianceScore: scoring.score,
    status: scoring.status,
  };
}
