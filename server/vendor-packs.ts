import fs from 'fs';
import path from 'path';
import { db, LearnedRule } from './db.ts';

export interface VendorPackRule {
  id?: string;
  name: string;
  field: string;
  regex: string;
  extractionType: 'capture_group' | 'presence_true' | 'presence_false' | 'static_value';
  captureGroupIndex?: number;
  staticValue?: any;
  sampleLine?: string;
  confidence?: number;
}

export interface VendorPack {
  vendorPackId: string;
  vendor: string;
  version: string;
  description: string;
  author?: string;
  updatedAt?: string;
  detectionSignatures?: Array<{ pattern: string; confidence?: number }>;
  rules: VendorPackRule[];
}

export class VendorPackManager {
  private dir: string;

  constructor() {
    this.dir = path.resolve(process.cwd(), 'data', 'vendor-packs');
    this.ensureDirAndSeed();
  }

  private ensureDirAndSeed(): void {
    if (!fs.existsSync(this.dir)) {
      fs.mkdirSync(this.dir, { recursive: true });
    }

    const files = fs.readdirSync(this.dir).filter(f => f.endsWith('.json'));
    if (files.length === 0) {
      this.seedDefaultPacks();
    }
  }

  private seedDefaultPacks(): void {
    const defaultPacks: VendorPack[] = [
      {
        vendorPackId: 'cisco-ios-pack',
        vendor: 'Cisco IOS-XE / IOS',
        version: '1.2.0',
        description: 'Normalization patterns and extraction rules for Cisco Catalyst, ISR, and ASR routers/switches running IOS and IOS-XE.',
        author: 'ZENTRA NetSec Core Team',
        updatedAt: new Date().toISOString(),
        detectionSignatures: [
          { pattern: 'version\\s+1[567]\\.[0-9]', confidence: 95 },
          { pattern: 'service\\s+timestamps', confidence: 85 },
        ],
        rules: [
          {
            id: 'cisco-rule-ssh',
            name: 'Cisco SSH Protocol Version',
            field: 'ssh_version',
            regex: 'ip\\s+ssh\\s+version\\s+(\\d+)',
            extractionType: 'capture_group',
            captureGroupIndex: 1,
            sampleLine: 'ip ssh version 2',
            confidence: 0.99,
          },
          {
            id: 'cisco-rule-keepalive-out',
            name: 'Cisco Service TCP Keepalives Out',
            field: 'service_tcp_keepalives',
            regex: 'service\\s+tcp-keepalives-out',
            extractionType: 'presence_true',
            sampleLine: 'service tcp-keepalives-out',
            confidence: 0.98,
          },
          {
            id: 'cisco-rule-password-encryption',
            name: 'Cisco Password Encryption',
            field: 'password_encryption',
            regex: 'service\\s+password-encryption',
            extractionType: 'presence_true',
            sampleLine: 'service password-encryption',
            confidence: 0.99,
          },
          {
            id: 'cisco-rule-http-server-disable',
            name: 'Cisco HTTP Web Management Disable',
            field: 'http_server_enabled',
            regex: 'no\\s+ip\\s+http\\s+server',
            extractionType: 'presence_false',
            sampleLine: 'no ip http server',
            confidence: 0.99,
          },
        ],
      },
      {
        vendorPackId: 'paloalto-panos-pack',
        vendor: 'Palo Alto PAN-OS',
        version: '2.1.0',
        description: 'Comprehensive syntax patterns and system baseline extractions for Palo Alto Next-Gen Firewalls running PAN-OS 10.x/11.x.',
        author: 'ZENTRA NetSec Core Team',
        updatedAt: new Date().toISOString(),
        detectionSignatures: [
          { pattern: 'set\\s+deviceconfig\\s+system', confidence: 95 },
          { pattern: 'panos|palo\\s*alto', confidence: 90 },
        ],
        rules: [
          {
            id: 'panos-rule-timeout',
            name: 'PAN-OS Admin Session Idle Timeout',
            field: 'session_timeout',
            regex: 'set\\s+deviceconfig\\s+system\\s+idle-timeout\\s+(\\d+)',
            extractionType: 'capture_group',
            captureGroupIndex: 1,
            sampleLine: 'set deviceconfig system idle-timeout 10',
            confidence: 0.99,
          },
          {
            id: 'panos-rule-ssh-version',
            name: 'PAN-OS SSH Protocol Version Enforce',
            field: 'ssh_version',
            regex: 'set\\s+deviceconfig\\s+system\\s+ssh-service\\s+protocol-version\\s+([\\w\\d.]+)',
            extractionType: 'capture_group',
            captureGroupIndex: 1,
            sampleLine: 'set deviceconfig system ssh-service protocol-version v2',
            confidence: 0.99,
          },
          {
            id: 'panos-rule-banner',
            name: 'PAN-OS Login Warning Banner',
            field: 'banner_set',
            regex: 'set\\s+deviceconfig\\s+system\\s+login-banner',
            extractionType: 'presence_true',
            sampleLine: 'set deviceconfig system login-banner "AUTHORIZED ACCESS ONLY"',
            confidence: 0.99,
          },
        ],
      },
      {
        vendorPackId: 'juniper-junos-pack',
        vendor: 'Juniper JunOS',
        version: '1.8.0',
        description: 'Hierarchical stanza and set-command extractors for Juniper SRX gateways, MX routers, and QFX switches.',
        author: 'ZENTRA NetSec Core Team',
        updatedAt: new Date().toISOString(),
        detectionSignatures: [
          { pattern: 'system\\s*\\{[\\s\\S]*root-authentication', confidence: 95 },
          { pattern: 'set\\s+system\\s+services', confidence: 90 },
        ],
        rules: [
          {
            id: 'junos-rule-ssh',
            name: 'JunOS SSH Service Protocol V2',
            field: 'ssh_version',
            regex: 'protocol-version\\s+v2|set\\s+system\\s+services\\s+ssh\\s+protocol-version\\s+v2',
            extractionType: 'presence_true',
            sampleLine: 'set system services ssh protocol-version v2',
            confidence: 0.99,
          },
          {
            id: 'junos-rule-telnet',
            name: 'JunOS Telnet Service Absence',
            field: 'telnet_enabled',
            regex: 'telnet\\s*;|set\\s+system\\s+services\\s+telnet',
            extractionType: 'presence_true',
            sampleLine: 'set system services telnet',
            confidence: 0.95,
          },
          {
            id: 'junos-rule-timeout',
            name: 'JunOS Login Session Timeout',
            field: 'session_timeout',
            regex: 'idle-timeout\\s+(\\d+)',
            extractionType: 'capture_group',
            captureGroupIndex: 1,
            sampleLine: 'idle-timeout 15;',
            confidence: 0.98,
          },
        ],
      },
      {
        vendorPackId: 'arista-eos-pack',
        vendor: 'Arista EOS',
        version: '1.5.0',
        description: 'EOS configuration patterns for datacenter spine and leaf switches (7050, 7060, 7280 series).',
        author: 'ZENTRA NetSec Core Team',
        updatedAt: new Date().toISOString(),
        detectionSignatures: [
          { pattern: 'management\\s+api\\s+http-commands', confidence: 95 },
          { pattern: 'daemon\\s+TerminAttr', confidence: 90 },
        ],
        rules: [
          {
            id: 'arista-rule-http-api',
            name: 'Arista HTTPS Management API',
            field: 'https_enabled',
            regex: 'protocol\\s+https',
            extractionType: 'presence_true',
            sampleLine: 'protocol https',
            confidence: 0.99,
          },
          {
            id: 'arista-rule-ssh-crypto',
            name: 'Arista SSH Modern Cipher Requirement',
            field: 'ssh_version',
            regex: 'ssh\\s+server\\s+cipher',
            extractionType: 'presence_true',
            sampleLine: 'ssh server cipher aes256-gcm@openssh.com',
            confidence: 0.95,
          },
        ],
      },
      {
        vendorPackId: 'fortinet-fortios-pack',
        vendor: 'Fortinet FortiOS',
        version: '1.0.0',
        description: 'FortiGate firewall CLI stanza parser for config system global, config system admin, and interface security policies.',
        author: 'ZENTRA NetSec Core Team',
        updatedAt: new Date().toISOString(),
        detectionSignatures: [
          { pattern: 'config\\s+system\\s+global', confidence: 95 },
          { pattern: 'set\\s+admintimeout', confidence: 90 },
        ],
        rules: [
          {
            id: 'fortinet-rule-http',
            name: 'Fortinet HTTP Administration Disable',
            field: 'http_server_enabled',
            regex: 'set\\s+admin-http\\s+(enable|disable)',
            extractionType: 'capture_group',
            captureGroupIndex: 1,
            sampleLine: 'set admin-http disable',
            confidence: 0.99,
          },
          {
            id: 'fortinet-rule-admintimeout',
            name: 'Fortinet Admin Idle Timeout Extractor',
            field: 'session_timeout',
            regex: 'set\\s+admintimeout\\s+(\\d+)',
            extractionType: 'capture_group',
            captureGroupIndex: 1,
            sampleLine: 'set admintimeout 10',
            confidence: 0.99,
          },
        ],
      },
    ];

    for (const pack of defaultPacks) {
      try {
        const filePath = path.join(this.dir, `${pack.vendorPackId}.json`);
        fs.writeFileSync(filePath, JSON.stringify(pack, null, 2), 'utf-8');
      } catch (err) {
        console.error('Failed to seed default vendor pack:', err);
      }
    }
  }

  public getAllPacks(): VendorPack[] {
    this.ensureDirAndSeed();
    const packs: VendorPack[] = [];
    const files = fs.readdirSync(this.dir).filter(f => f.endsWith('.json'));

    for (const file of files) {
      try {
        const fullPath = path.join(this.dir, file);
        const raw = fs.readFileSync(fullPath, 'utf-8');
        const parsed = JSON.parse(raw) as VendorPack;
        if (parsed.vendorPackId && parsed.vendor && Array.isArray(parsed.rules)) {
          packs.push(parsed);
        }
      } catch (err) {
        console.error(`Failed to read vendor pack file ${file}:`, err);
      }
    }

    return packs;
  }

  public getPack(vendorPackId: string): VendorPack | undefined {
    return this.getAllPacks().find(p => p.vendorPackId === vendorPackId);
  }

  public savePack(pack: VendorPack, userName?: string): void {
    this.ensureDirAndSeed();
    const cleanId = (pack.vendorPackId || pack.vendor.toLowerCase().replace(/[^a-z0-9_-]/g, '-')).toLowerCase();
    pack.vendorPackId = cleanId;
    pack.updatedAt = new Date().toISOString();

    const filePath = path.join(this.dir, `${cleanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify(pack, null, 2), 'utf-8');

    // Synchronize rules into db.learnedRules so normalizer immediately has them available at runtime
    if (Array.isArray(pack.rules)) {
      for (const r of pack.rules) {
        const existingIdx = db.learnedRules.findIndex(
          lr => lr.vendor.toLowerCase() === pack.vendor.toLowerCase() && lr.regex === r.regex
        );

        const learnedRule: LearnedRule = {
          id: r.id || `rule-vp-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
          name: r.name || `${pack.vendor} ${r.field}`,
          vendor: pack.vendor,
          regex: r.regex,
          field: r.field,
          extractionType: r.extractionType || 'capture_group',
          captureGroupIndex: r.captureGroupIndex ?? 1,
          staticValue: r.staticValue ?? null,
          sampleLine: r.sampleLine || '',
          confidence: r.confidence ?? 0.98,
          createdAt: new Date().toISOString(),
          createdBy: userName || 'Vendor Pack Import',
        };

        if (existingIdx !== -1) {
          db.learnedRules[existingIdx] = learnedRule;
        } else {
          db.learnedRules.unshift(learnedRule);
        }
      }
      db.persist();
    }
  }

  public deletePack(vendorPackId: string): boolean {
    this.ensureDirAndSeed();
    const filePath = path.join(this.dir, `${vendorPackId}.json`);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      return true;
    }
    return false;
  }

  // Export vendor pack for a specific vendor, pulling in both file rules and runtime learned rules
  public exportPackForVendor(vendorName: string): VendorPack {
    const existingPack = this.getAllPacks().find(p => p.vendor.toLowerCase() === vendorName.toLowerCase());
    const rulesFromDb = db.learnedRules
      .filter(r => r.vendor.toLowerCase() === vendorName.toLowerCase() || r.vendor === 'ALL')
      .map(r => ({
        id: r.id,
        name: r.name,
        field: r.field,
        regex: r.regex,
        extractionType: r.extractionType,
        captureGroupIndex: r.captureGroupIndex,
        staticValue: r.staticValue,
        sampleLine: r.sampleLine,
        confidence: r.confidence,
      }));

    if (existingPack) {
      // Merge rules without duplicate regexes
      const ruleMap = new Map<string, VendorPackRule>();
      existingPack.rules.forEach(r => ruleMap.set(r.regex, r));
      rulesFromDb.forEach(r => ruleMap.set(r.regex, r));

      return {
        ...existingPack,
        rules: Array.from(ruleMap.values()),
        updatedAt: new Date().toISOString(),
      };
    }

    return {
      vendorPackId: `${vendorName.toLowerCase().replace(/[^a-z0-9_-]/g, '-')}-pack`,
      vendor: vendorName,
      version: '1.0.0',
      description: `Exported normalization rule pack for ${vendorName}`,
      author: 'ZENTRA NetSec Engine Export',
      updatedAt: new Date().toISOString(),
      rules: rulesFromDb,
    };
  }
}

export const vendorPackManager = new VendorPackManager();
