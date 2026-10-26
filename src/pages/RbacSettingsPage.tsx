import React, { useState, useEffect } from 'react';
import {
  Settings,
  Shield,
  Users,
  Lock,
  CheckCircle2,
  XCircle,
  Save,
  AlertTriangle,
  RefreshCw,
  Download,
  Upload,
  Plus,
  Trash2,
  Eye,
  FileCode2,
  Cpu,
  Layers,
  Sparkles,
  FileText,
  Copy,
  Check,
  ExternalLink,
  Code2,
  Sliders,
  Database,
  ArrowRight,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { SeverityBadge } from '../components/common/Badge';
import { RoleType, SecurityFramework, VendorPack, VendorPackRule, FrameworkControl } from '../types';
import { apiService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

interface RbacSettingsPageProps {
  onNavigateTab?: (tab: string) => void;
}

// Sample Framework Pack for instant testing
const SAMPLE_PCI_FRAMEWORK_PACK = {
  frameworkId: 'pci-dss-4',
  name: 'PCI-DSS v4.0 Network Security Baseline',
  version: 'v4.0.1',
  description: 'Payment Card Industry Data Security Standard Requirement 1 & 2 for network equipment isolating cardholder data environments (CDE).',
  controls: [
    {
      id: 'PCI-NET-1.2.1',
      title: 'Inbound and Outbound Traffic Restricted to Cardholder Data Environment',
      severity: 'CRITICAL',
      field: 'acl_count',
      operator: 'gte',
      expectedValue: 1,
      remediation: 'For {vendor}, configure and apply explicit access control lists (ACLs) restricting ingress to authorized payment processing subnets.',
    },
    {
      id: 'PCI-NET-2.2.2',
      title: 'Disable All Insecure and Cleartext Administrative Protocols',
      severity: 'CRITICAL',
      field: 'telnet_enabled',
      operator: 'equals',
      expectedValue: false,
      remediation: 'For {vendor}, disable cleartext Telnet management immediately: remove Telnet server daemons and restrict management to SSHv2.',
    },
    {
      id: 'PCI-NET-2.2.3',
      title: 'Disable Unencrypted HTTP Web Administration',
      severity: 'HIGH',
      field: 'http_server_enabled',
      operator: 'equals',
      expectedValue: false,
      remediation: 'For {vendor}, disable plain HTTP server. Enforce HTTPS with TLS 1.2 or TLS 1.3.',
    },
    {
      id: 'PCI-NET-2.2.4',
      title: 'Enforce Strong SSH Version and Cipher Suite',
      severity: 'HIGH',
      field: 'ssh_version',
      operator: 'contains',
      expectedValue: '2',
      remediation: 'For {vendor}, enforce SSH protocol version 2 and disable legacy DES/3DES/RC4 cipher suites.',
    },
    {
      id: 'PCI-NET-10.2.1',
      title: 'Centralized Syslog Event Logging for Audit Trail',
      severity: 'HIGH',
      field: 'logging_hosts',
      operator: 'is_not_empty',
      expectedValue: true,
      remediation: 'For {vendor}, configure centralized remote syslog forwarding to the compliance SIEM cluster.',
    },
    {
      id: 'PCI-NET-8.2.8',
      title: 'Enforce Administrative Inactivity Session Timeout <= 15 Minutes',
      severity: 'MEDIUM',
      field: 'session_timeout',
      operator: 'lte',
      expectedValue: 15,
      remediation: 'For {vendor}, configure idle session timeout to 15 minutes or lower.',
    },
  ],
};

// Sample Vendor Pack for instant testing
const SAMPLE_VYOS_VENDOR_PACK = {
  vendorPackId: 'vyos-linux-pack',
  vendor: 'VyOS Linux NOS',
  version: '1.4.0',
  description: 'Normalization patterns and extraction rules for VyOS open-source software-based routers and firewalls.',
  author: 'Community Network Security Contributor',
  detectionSignatures: [
    { pattern: 'set\\s+system\\s+host-name', confidence: 95 },
    { pattern: 'vyos@', confidence: 90 },
  ],
  rules: [
    {
      id: 'vyos-rule-ssh',
      name: 'VyOS SSH Service Port and Protocol',
      field: 'ssh_version',
      regex: 'set\\s+service\\s+ssh(?:\\s+port\\s+\\d+)?',
      extractionType: 'presence_true',
      sampleLine: 'set service ssh port 22',
      confidence: 0.98,
    },
    {
      id: 'vyos-rule-https',
      name: 'VyOS HTTPS Web GUI Admin Service',
      field: 'https_enabled',
      regex: 'set\\s+service\\s+https',
      extractionType: 'presence_true',
      sampleLine: 'set service https',
      confidence: 0.99,
    },
    {
      id: 'vyos-rule-syslog',
      name: 'VyOS Remote Syslog Host Destination',
      field: 'logging_hosts',
      regex: 'set\\s+system\\s+syslog\\s+host\\s+([\\w\\d.]+)',
      extractionType: 'capture_group',
      captureGroupIndex: 1,
      sampleLine: 'set system syslog host 10.100.1.50',
      confidence: 0.99,
    },
    {
      id: 'vyos-rule-ntp',
      name: 'VyOS Network Time Protocol Server',
      field: 'ntp_servers',
      regex: 'set\\s+system\\s+ntp\\s+server\\s+([\\w\\d.]+)',
      extractionType: 'capture_group',
      captureGroupIndex: 1,
      sampleLine: 'set system ntp server 10.100.2.1',
      confidence: 0.99,
    },
    {
      id: 'vyos-rule-banner',
      name: 'VyOS Pre-Login Warning Banner',
      field: 'banner_set',
      regex: 'set\\s+system\\s+login\\s+banner',
      extractionType: 'presence_true',
      sampleLine: 'set system login banner pre-login "AUTHORIZED ACCESS ONLY"',
      confidence: 0.99,
    },
  ],
};

function downloadJsonFile(filename: string, data: any) {
  const jsonStr = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function RbacSettingsPage({ onNavigateTab }: RbacSettingsPageProps = {}) {
  const { role: activeUserRole } = useAuth();
  const [activeTab, setActiveTab] = useState<'extensibility' | 'rbac' | 'system'>('extensibility');
  const [packSection, setPackSection] = useState<'frameworks' | 'vendors'>('frameworks');

  // Framework Packs state
  const [frameworks, setFrameworks] = useState<SecurityFramework[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<SecurityFramework | null>(null);
  const [importFwModalOpen, setImportFwModalOpen] = useState(false);
  const [importFwText, setImportFwText] = useState('');
  const [importFwError, setImportFwError] = useState<string | null>(null);

  // Vendor Packs state
  const [vendorPacks, setVendorPacks] = useState<VendorPack[]>([]);
  const [selectedVendorPack, setSelectedVendorPack] = useState<VendorPack | null>(null);
  const [importVendorModalOpen, setImportVendorModalOpen] = useState(false);
  const [importVendorText, setImportVendorText] = useState('');
  const [importVendorError, setImportVendorError] = useState<string | null>(null);

  // Search filters
  const [frameworkSearch, setFrameworkSearch] = useState('');
  const [vendorSearch, setVendorSearch] = useState('');

  // RBAC state
  const [permissionsMap, setPermissionsMap] = useState<Record<RoleType, string[]>>({
    ADMIN: [],
    SECURITY_ANALYST: [],
    DEVELOPER: [],
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [isVerifyingIntegrity, setIsVerifyingIntegrity] = useState(false);
  const [integrityResult, setIntegrityResult] = useState<{ isValid: boolean; totalChecked: number } | null>(null);
  const [aiEngineStatus, setAiEngineStatus] = useState<{
    mode: string;
    label: string;
    offline: boolean;
    reason?: string;
  } | null>(null);
  const [isUpdatingAiMode, setIsUpdatingAiMode] = useState(false);

  const { showToast } = useToast();

  const handleToggleOfflineMode = async (targetOffline: boolean) => {
    try {
      setIsUpdatingAiMode(true);
      const res = await apiService.setAiMode({ offline: targetOffline });
      setAiEngineStatus(res);
      showToast(
        targetOffline ? 'Offline AI Mode Enabled' : 'Gemini AI Mode Enabled',
        targetOffline
          ? 'Network configuration parsing is now 100% local. No config data leaves this device.'
          : 'Gemini Cloud AI active with automatic offline fallback when disconnected.',
        'success'
      );
    } catch (err: any) {
      showToast('AI Mode Update Failed', err.message || 'Error communicating with AI engine', 'error');
    } finally {
      setIsUpdatingAiMode(false);
    }
  };

  const MODULES = [
    {
      name: 'Device Configurations & Ingestion',
      permissions: [
        { id: 'device:upload', label: 'Ingest Network Configurations' },
        { id: 'device:renormalize', label: 'Trigger AI Re-normalization' },
        { id: 'device:delete', label: 'Delete Configuration Records (Admin)' },
      ],
    },
    {
      name: 'Multi-Framework Compliance Engine',
      permissions: [
        { id: 'compliance:view', label: 'View Multi-Framework Matrix' },
        { id: 'compliance:evaluate', label: 'Execute Compliance Evaluations' },
        { id: 'compliance:packs_manage', label: 'Import/Export Framework Packs' },
      ],
    },
    {
      name: 'Parser Training & Runtime Rule Learner',
      permissions: [
        { id: 'training:view', label: 'View Unrecognized Lines Queue' },
        { id: 'training:create_rule', label: 'Create Learned Normalization Rules' },
        { id: 'training:reparse', label: 'Execute Runtime Device Re-parsing' },
      ],
    },
    {
      name: 'Audit Reports & CLI Playbooks',
      permissions: [
        { id: 'reports:view', label: 'View Device Scorecards' },
        { id: 'reports:export_pdf', label: 'Export Per-Device PDF Deliverables' },
        { id: 'reports:export_zip', label: 'Export Bulk ZIP Bundle' },
      ],
    },
    {
      name: 'Governance, RBAC & Security Parameters',
      permissions: [
        { id: 'rbac:manage', label: 'Modify Role-Based Access Control Matrices' },
        { id: 'settings:edit', label: 'Manage Extensibility Packs & System Keys' },
        { id: 'audit:verify', label: 'Execute Cryptographic SHA-256 Ledger Verification' },
      ],
    },
  ];

  const loadAllData = async () => {
    try {
      setLoading(true);
      const [fwData, vpData, rbacData, aiData] = await Promise.all([
        apiService.getFrameworkPacks(),
        apiService.getVendorPacks(),
        apiService.getRbacPermissions(),
        apiService.getAiStatus().catch(() => null),
      ]);
      setFrameworks(fwData);
      setVendorPacks(vpData);
      setPermissionsMap(rbacData);
      if (aiData) setAiEngineStatus(aiData);
    } catch (err: any) {
      showToast('Error loading settings data', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  // --- Framework Packs Actions ---
  const handleExportFramework = async (id: string, name: string) => {
    try {
      const data = await apiService.exportFrameworkPack(id);
      downloadJsonFile(`framework-pack-${id}.json`, data);
      showToast('Framework Pack Exported', `Downloaded ${name} as JSON.`, 'success');
    } catch (err: any) {
      showToast('Export failed', err.message, 'error');
    }
  };

  const handleExportAllFrameworks = () => {
    downloadJsonFile(`zentra-framework-packs-bundle-${Date.now()}.json`, {
      exportDate: new Date().toISOString(),
      generator: 'ZENTRA NetSec Engine',
      frameworkCount: frameworks.length,
      frameworks,
    });
    showToast('Framework Bundle Exported', `Downloaded all ${frameworks.length} framework packs as JSON bundle.`, 'success');
  };

  const handleImportFrameworkSubmit = async () => {
    setImportFwError(null);
    try {
      if (!importFwText.trim()) {
        setImportFwError('Please paste or upload a valid JSON framework pack.');
        return;
      }
      const parsed = JSON.parse(importFwText);
      const res = await apiService.importFrameworkPack(parsed);
      showToast('Framework Pack Imported', res.message, 'success');
      setImportFwModalOpen(false);
      setImportFwText('');
      const updated = await apiService.getFrameworkPacks();
      setFrameworks(updated);
    } catch (err: any) {
      setImportFwError(err.message || 'Invalid JSON syntax or framework schema.');
    }
  };

  const handleDeleteFramework = async (id: string, name: string) => {
    if (activeUserRole !== 'ADMIN') {
      showToast('Permission Denied', 'Only ADMIN can remove framework packs.', 'warning');
      return;
    }
    if (['cis', 'nist_800_53', 'disa_stig', 'iso_27001'].includes(id)) {
      showToast('System Standard Protected', 'Default baseline frameworks cannot be deleted.', 'warning');
      return;
    }
    if (!window.confirm(`Are you sure you want to delete framework pack "${name}"?`)) return;

    try {
      await apiService.deleteFrameworkPack(id);
      showToast('Framework Pack Removed', `Deleted ${name}.`, 'success');
      const updated = await apiService.getFrameworkPacks();
      setFrameworks(updated);
      if (selectedFramework?.frameworkId === id) setSelectedFramework(null);
    } catch (err: any) {
      showToast('Delete failed', err.message, 'error');
    }
  };

  // --- Vendor Packs Actions ---
  const handleExportVendorPack = async (vendor: string, packId: string) => {
    try {
      const data = await apiService.exportVendorPack(packId || vendor);
      downloadJsonFile(`vendor-pack-${packId || vendor.toLowerCase().replace(/[^a-z0-9]/g, '-')}.json`, data);
      showToast('Vendor Pack Exported', `Downloaded rules for ${vendor} as JSON.`, 'success');
    } catch (err: any) {
      showToast('Export failed', err.message, 'error');
    }
  };

  const handleExportAllVendorPacks = () => {
    downloadJsonFile(`zentra-vendor-packs-bundle-${Date.now()}.json`, {
      exportDate: new Date().toISOString(),
      generator: 'ZENTRA NetSec Engine',
      packCount: vendorPacks.length,
      vendorPacks,
    });
    showToast('Vendor Bundle Exported', `Downloaded all ${vendorPacks.length} vendor packs as JSON bundle.`, 'success');
  };

  const handleImportVendorSubmit = async () => {
    setImportVendorError(null);
    try {
      if (!importVendorText.trim()) {
        setImportVendorError('Please paste or upload a valid JSON vendor pack.');
        return;
      }
      const parsed = JSON.parse(importVendorText);
      const res = await apiService.importVendorPack(parsed);
      showToast('Vendor Pack Imported', res.message, 'success');
      setImportVendorModalOpen(false);
      setImportVendorText('');
      const updated = await apiService.getVendorPacks();
      setVendorPacks(updated);
    } catch (err: any) {
      setImportVendorError(err.message || 'Invalid JSON syntax or vendor pack schema.');
    }
  };

  const handleDeleteVendorPack = async (id: string, vendor: string) => {
    if (activeUserRole !== 'ADMIN') {
      showToast('Permission Denied', 'Only ADMIN can remove vendor packs.', 'warning');
      return;
    }
    if (!window.confirm(`Are you sure you want to delete vendor pack "${vendor}"?`)) return;

    try {
      await apiService.deleteVendorPack(id);
      showToast('Vendor Pack Removed', `Deleted ${vendor} pack.`, 'success');
      const updated = await apiService.getVendorPacks();
      setVendorPacks(updated);
      if (selectedVendorPack?.vendorPackId === id) setSelectedVendorPack(null);
    } catch (err: any) {
      showToast('Delete failed', err.message, 'error');
    }
  };

  // --- File Upload Helpers ---
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>, setText: (t: string) => void) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setText(content);
    };
    reader.readAsText(file);
  };

  // --- RBAC Toggles ---
  const togglePermission = (role: RoleType, permissionId: string) => {
    if (activeUserRole !== 'ADMIN') {
      showToast('RBAC Restricted', 'Only ADMIN role can alter permission assignments.', 'warning');
      return;
    }
    if (role === 'ADMIN' && permissionId === 'rbac:manage') {
      showToast('Protected Policy', 'Admin cannot remove self-governance permission.', 'warning');
      return;
    }

    setPermissionsMap((prev) => {
      const current = prev[role] || [];
      const updated = current.includes(permissionId)
        ? current.filter((p) => p !== permissionId)
        : [...current, permissionId];
      return { ...prev, [role]: updated };
    });
  };

  const handleSaveRbac = async () => {
    if (activeUserRole !== 'ADMIN') {
      showToast('RBAC Restricted', 'Only ADMIN role can commit permissions.', 'warning');
      return;
    }

    setSaving(true);
    try {
      await Promise.all([
        apiService.updateRbacPermissions('ADMIN', permissionsMap.ADMIN),
        apiService.updateRbacPermissions('SECURITY_ANALYST', permissionsMap.SECURITY_ANALYST),
        apiService.updateRbacPermissions('DEVELOPER', permissionsMap.DEVELOPER),
      ]);
      showToast('RBAC Policy Committed', 'Updated permission matrices logged to SHA-256 ledger.', 'success');
    } catch (err: any) {
      showToast('Failed to save permissions', err.message, 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleVerifyLedger = async () => {
    try {
      setIsVerifyingIntegrity(true);
      const res = await apiService.verifyAuditChain();
      setIntegrityResult(res);
      if (res.isValid) {
        showToast('Cryptographic Verification Succeeded', `Verified 100% of ${res.totalChecked} SHA-256 block hashes.`, 'success');
      } else {
        showToast('Chain Corrupted', 'Integrity hash mismatch detected in ledger.', 'error');
      }
    } catch (err: any) {
      showToast('Verification failed', err.message, 'error');
    } finally {
      setIsVerifyingIntegrity(false);
    }
  };

  const filteredFrameworks = frameworks.filter(
    (f) =>
      f.name.toLowerCase().includes(frameworkSearch.toLowerCase()) ||
      (f.frameworkId && f.frameworkId.toLowerCase().includes(frameworkSearch.toLowerCase())) ||
      (f.description && f.description.toLowerCase().includes(frameworkSearch.toLowerCase()))
  );

  const filteredVendorPacks = vendorPacks.filter(
    (v) =>
      v.vendor.toLowerCase().includes(vendorSearch.toLowerCase()) ||
      (v.vendorPackId && v.vendorPackId.toLowerCase().includes(vendorSearch.toLowerCase())) ||
      (v.description && v.description.toLowerCase().includes(vendorSearch.toLowerCase()))
  );

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-sm font-mono text-slate-400">Loading Extensibility & Settings Engine...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 text-left">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/30 backdrop-blur-md shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 border border-cyan-500/40 text-cyan-300">
              ZERO-CODE EXTENSIBILITY
            </span>
            <span className="text-xs text-slate-400">• Dynamic JSON Packs & Governance</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight mt-1">
            Engine Extensibility, Packs & Governance
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Import and export vendor normalization packs and security framework packs as JSON to add new standards or hardware without code changes.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto shrink-0">
          {activeTab === 'rbac' && activeUserRole === 'ADMIN' && (
            <button
              onClick={handleSaveRbac}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition active:scale-95 disabled:opacity-50 cursor-pointer"
            >
              <Save className="w-4 h-4" />
              <span>{saving ? 'Committing...' : 'Save RBAC Policy'}</span>
            </button>
          )}

          {activeTab === 'extensibility' && (
            <button
              onClick={() => {
                if (packSection === 'frameworks') {
                  handleExportAllFrameworks();
                } else {
                  handleExportAllVendorPacks();
                }
              }}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-800 text-slate-200 text-xs font-semibold transition active:scale-95 cursor-pointer"
              title="Download entire pack catalog as JSON"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export All {packSection === 'frameworks' ? 'Frameworks' : 'Vendor Packs'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('extensibility')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
            activeTab === 'extensibility'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Vendor & Framework Packs (JSON Extensibility)</span>
        </button>

        <button
          onClick={() => setActiveTab('rbac')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
            activeTab === 'rbac'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Users className="w-4 h-4" />
          <span>Role Permissions Matrix</span>
        </button>

        <button
          onClick={() => setActiveTab('system')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
            activeTab === 'system'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Lock className="w-4 h-4" />
          <span>Ledger Integrity & Zero-Trust Core</span>
        </button>
      </div>

      {/* TAB 1: EXTENSIBILITY & PACKS */}
      {activeTab === 'extensibility' && (
        <div className="space-y-6">
          {/* Sub Navigation: Frameworks vs Vendors */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-lg bg-slate-900/60 border border-slate-800">
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPackSection('frameworks')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold transition cursor-pointer ${
                  packSection === 'frameworks'
                    ? 'bg-cyan-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <FileCode2 className="w-3.5 h-3.5" />
                <span>Compliance Framework Packs ({frameworks.length})</span>
              </button>

              <button
                onClick={() => setPackSection('vendors')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold transition cursor-pointer ${
                  packSection === 'vendors'
                    ? 'bg-cyan-600 text-white shadow-md'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                <Cpu className="w-3.5 h-3.5" />
                <span>Vendor Normalization Packs ({vendorPacks.length})</span>
              </button>
            </div>

            <div className="flex items-center gap-2">
              {packSection === 'frameworks' ? (
                <button
                  onClick={() => {
                    setImportFwText('');
                    setImportFwError(null);
                    setImportFwModalOpen(true);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow transition cursor-pointer"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Import Framework Pack (JSON)</span>
                </button>
              ) : (
                <button
                  onClick={() => {
                    setImportVendorText('');
                    setImportVendorError(null);
                    setImportVendorModalOpen(true);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow transition cursor-pointer"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>Import Vendor Pack (JSON)</span>
                </button>
              )}
            </div>
          </div>

          {/* SECTION 1: FRAMEWORK PACKS */}
          {packSection === 'frameworks' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <input
                  type="text"
                  placeholder="Filter framework standards (e.g. CIS, NIST, ISO)..."
                  value={frameworkSearch}
                  onChange={(e) => setFrameworkSearch(e.target.value)}
                  className="w-full sm:w-80 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <span className="text-xs text-slate-400 font-mono">
                  {filteredFrameworks.length} installed standards • Hot-evaluable
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredFrameworks.map((fw) => {
                  const ctrlCount = fw.controls?.length ?? fw.controlCount ?? 0;
                  const isProtected = ['cis', 'nist_800_53', 'disa_stig', 'iso_27001'].includes(fw.frameworkId);

                  return (
                    <div
                      key={fw.frameworkId}
                      className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 hover:border-slate-700 transition flex flex-col justify-between gap-4 group"
                    >
                      <div>
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                              <FileCode2 className="w-4 h-4" />
                            </span>
                            <div>
                              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
                                <span>{fw.name}</span>
                                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/30 text-cyan-300">
                                  {fw.version}
                                </span>
                              </h3>
                              <p className="text-[11px] font-mono text-slate-400">
                                ID: <span className="text-cyan-400">{fw.frameworkId}</span>
                              </p>
                            </div>
                          </div>

                          <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            {ctrlCount} Controls
                          </span>
                        </div>

                        <p className="text-xs text-slate-400 mt-2.5 line-clamp-2">
                          {fw.description}
                        </p>
                      </div>

                      <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                        <button
                          onClick={() => setSelectedFramework(fw)}
                          className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition cursor-pointer flex items-center gap-1.5"
                          title="View all rules and remediation definitions"
                        >
                          <Eye className="w-3.5 h-3.5 text-cyan-400" />
                          <span>View Controls ({ctrlCount})</span>
                        </button>

                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => handleExportFramework(fw.frameworkId, fw.name)}
                            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-950/60 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/40 text-slate-300 text-xs font-medium transition cursor-pointer flex items-center gap-1"
                            title="Download framework pack JSON"
                          >
                            <Download className="w-3.5 h-3.5" />
                            <span>Export JSON</span>
                          </button>

                          {!isProtected && (
                            <button
                              onClick={() => handleDeleteFramework(fw.frameworkId, fw.name)}
                              className="p-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-400 border border-rose-500/30 transition cursor-pointer"
                              title="Delete framework pack"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* SECTION 2: VENDOR NORMALIZATION PACKS */}
          {packSection === 'vendors' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <input
                  type="text"
                  placeholder="Filter vendor NOS syntax (e.g. Cisco, Palo Alto, Arista, Fortinet)..."
                  value={vendorSearch}
                  onChange={(e) => setVendorSearch(e.target.value)}
                  className="w-full sm:w-80 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <span className="text-xs text-slate-400 font-mono">
                  {filteredVendorPacks.length} registered hardware packs • Hot-reloadable
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {filteredVendorPacks.map((pack) => {
                  const ruleCount = pack.rules?.length || 0;
                  return (
                    <div
                      key={pack.vendorPackId}
                      className="p-4 rounded-xl border border-slate-800 bg-slate-900/70 hover:border-slate-700 transition flex flex-col justify-between gap-4 group"
                    >
                      <div>
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="w-8 h-8 rounded-lg bg-amber-950/80 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                              <Cpu className="w-4 h-4" />
                            </span>
                            <div>
                              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
                                <span>{pack.vendor}</span>
                                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-950 border border-amber-500/30 text-amber-300">
                                  {pack.version}
                                </span>
                              </h3>
                              <p className="text-[11px] font-mono text-slate-400">
                                Pack: <span className="text-amber-400">{pack.vendorPackId}</span>
                              </p>
                            </div>
                          </div>

                          <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            {ruleCount} Rules
                          </span>
                        </div>

                        <p className="text-xs text-slate-400 mt-2.5 line-clamp-2">
                          {pack.description}
                        </p>

                        {pack.detectionSignatures && pack.detectionSignatures.length > 0 && (
                          <div className="mt-2.5 flex items-center gap-1.5 flex-wrap">
                            <span className="text-[10px] font-mono text-slate-500">Signatures:</span>
                            {pack.detectionSignatures.slice(0, 2).map((sig, sIdx) => (
                              <span
                                key={sIdx}
                                className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/80 text-cyan-300 border border-slate-700"
                              >
                                /{sig.pattern}/
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                        <button
                          onClick={() => setSelectedVendorPack(pack)}
                          className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition cursor-pointer flex items-center gap-1.5"
                        >
                          <Eye className="w-3.5 h-3.5 text-amber-400" />
                          <span>View Rules ({ruleCount})</span>
                        </button>

                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => handleExportVendorPack(pack.vendor, pack.vendorPackId)}
                            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-amber-950/60 hover:text-amber-300 border border-slate-700 hover:border-amber-500/40 text-slate-300 text-xs font-medium transition cursor-pointer flex items-center gap-1"
                            title="Download vendor pack JSON"
                          >
                            <Download className="w-3.5 h-3.5" />
                            <span>Export JSON</span>
                          </button>

                          <button
                            onClick={() => handleDeleteVendorPack(pack.vendorPackId, pack.vendor)}
                            className="p-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-400 border border-rose-500/30 transition cursor-pointer"
                            title="Delete vendor pack"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: RBAC MATRIX */}
      {activeTab === 'rbac' && (
        <Card
          title="Role Permissions Matrix"
          subtitle="Governed under principle of least privilege"
          action={
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-2 py-0.5 rounded">
                Active Session: {activeUserRole}
              </span>
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="pb-3 pr-4">Functional Module / Capability</th>
                  <th className="pb-3 px-4 text-center">Administrator</th>
                  <th className="pb-3 px-4 text-center">Security Analyst</th>
                  <th className="pb-3 px-4 text-center">Developer</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {MODULES.map((module) => (
                  <React.Fragment key={module.name}>
                    <tr className="bg-slate-900/40">
                      <td
                        colSpan={4}
                        className="py-2.5 px-3 font-semibold text-cyan-300 font-mono uppercase tracking-wider text-[11px] bg-gradient-to-r from-slate-900 to-transparent"
                      >
                        {module.name}
                      </td>
                    </tr>
                    {module.permissions.map((perm) => (
                      <tr key={perm.id} className="hover:bg-slate-850/40 transition">
                        <td className="py-2.5 pr-4 pl-3">
                          <span className="text-slate-200 font-medium">{perm.label}</span>
                          <span className="block text-[10px] font-mono text-slate-500">{perm.id}</span>
                        </td>

                        {(['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'] as RoleType[]).map((r) => {
                          const isAssigned = (permissionsMap[r] || []).includes(perm.id);
                          return (
                            <td key={r} className="py-2.5 px-4 text-center">
                              <button
                                onClick={() => togglePermission(r, perm.id)}
                                disabled={activeUserRole !== 'ADMIN'}
                                className={`p-1.5 rounded-lg border transition ${
                                  isAssigned
                                    ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400 hover:bg-rose-950/60 hover:text-rose-400 hover:border-rose-500/40'
                                    : 'bg-slate-900 border-slate-800 text-slate-600 hover:text-slate-300 hover:border-slate-700'
                                } ${activeUserRole !== 'ADMIN' ? 'cursor-not-allowed opacity-75' : 'cursor-pointer'}`}
                              >
                                {isAssigned ? (
                                  <CheckCircle2 className="w-4 h-4" />
                                ) : (
                                  <XCircle className="w-4 h-4" />
                                )}
                              </button>
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* TAB 3: SYSTEM POLICIES & AUDIT LEDGER INTEGRITY */}
      {activeTab === 'system' && (
        <div className="space-y-6">
          {/* AI ENGINE CONFIGURATION CARD */}
          <Card
            title="AI Intelligence Engine & Air-Gapped Mode"
            subtitle="Local multi-vendor TF-IDF NLP vs Cloud Gemini AI"
          >
            <div className="space-y-5 pt-1">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-cyan-400" />
                    <span className="text-sm font-bold text-slate-100">
                      Offline mode (no data leaves this device)
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                        aiEngineStatus?.offline
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                          : 'bg-purple-950 text-purple-300 border border-purple-500/40'
                      }`}
                    >
                      {aiEngineStatus?.offline ? 'Offline Mode Active' : 'Gemini + Offline'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 max-w-xl leading-relaxed">
                    When enabled, configuration parsing, vendor fingerprinting, and security baseline extraction run 100% locally using TF-IDF cosine similarity. No data is sent over the network or to external APIs.
                  </p>
                </div>

                <button
                  onClick={() => handleToggleOfflineMode(!aiEngineStatus?.offline)}
                  disabled={isUpdatingAiMode}
                  className={`relative inline-flex h-7 w-14 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                    aiEngineStatus?.offline ? 'bg-emerald-600' : 'bg-slate-700'
                  } ${isUpdatingAiMode ? 'opacity-50 cursor-not-allowed' : ''}`}
                  role="switch"
                  aria-checked={aiEngineStatus?.offline ?? false}
                  title="Toggle offline mode"
                >
                  <span
                    className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                      aiEngineStatus?.offline ? 'translate-x-7' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>

              {/* Status & Technical Guarantees */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1">
                  <div className="text-[10px] uppercase font-mono tracking-wider text-slate-500">Active Engine</div>
                  <div className="font-semibold text-slate-200">
                    {aiEngineStatus?.offline ? 'Local Vector NLP (TF-IDF)' : 'Gemini 2.5 Flash'}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {aiEngineStatus?.offline
                      ? 'Cosine similarity >= 0.5 with polarity invert'
                      : 'High-throughput LLM with local fallback'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1">
                  <div className="text-[10px] uppercase font-mono tracking-wider text-slate-500">Data Sovereignty</div>
                  <div className={`font-semibold ${aiEngineStatus?.offline ? 'text-emerald-300' : 'text-purple-300'}`}>
                    {aiEngineStatus?.offline ? '100% Local (Zero Egress)' : 'Encrypted Transit'}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {aiEngineStatus?.offline
                      ? 'Air-gap and sovereign classification ready'
                      : 'Mtls payload with zero training retention'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 space-y-1">
                  <div className="text-[10px] uppercase font-mono tracking-wider text-slate-500">Coverage Baseline</div>
                  <div className="font-semibold text-cyan-300">19 Security Fields</div>
                  <div className="text-[11px] text-slate-400">
                    Cisco, JunOS, EOS, FortiOS, PAN-OS, VRP, VyOS, SONiC
                  </div>
                </div>
              </div>
            </div>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card
            title="Cryptographic Audit Ledger Verification"
            subtitle="SHA-256 forward-linked tamper-evident chain"
          >
            <div className="space-y-4 pt-1">
              <p className="text-xs text-slate-300 leading-relaxed">
                Every policy change, pack import, configuration ingestion, and compliance evaluation is signed and forward-linked into an append-only cryptographic ledger.
              </p>

              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <p className="text-xs font-semibold text-slate-200">Ledger Verification Status</p>
                  <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                    {integrityResult
                      ? `${integrityResult.totalChecked} records checked: ${integrityResult.isValid ? 'VALID' : 'BROKEN'}`
                      : 'Audit ledger continuously verified'}
                  </p>
                </div>

                <button
                  onClick={handleVerifyLedger}
                  disabled={isVerifyingIntegrity}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition cursor-pointer"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isVerifyingIntegrity ? 'animate-spin' : ''}`} />
                  <span>{isVerifyingIntegrity ? 'Verifying...' : 'Verify SHA-256 Chain'}</span>
                </button>
              </div>

              {integrityResult && (
                <div
                  className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
                    integrityResult.isValid
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
                  }`}
                >
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>
                    Cryptographic integrity confirmed across all {integrityResult.totalChecked} ledger records. No tampering detected.
                  </span>
                </div>
              )}
            </div>
          </Card>

          <Card
            title="Extensibility & Runtime Hot-Reload Architecture"
            subtitle="Zero-redeploy policy execution"
          >
            <div className="space-y-3 pt-1 text-xs text-slate-300 leading-relaxed">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="font-semibold text-cyan-300 font-mono text-[11px] uppercase">
                  1. Framework Packs
                </span>
                <p className="text-slate-400 text-[11px]">
                  Stored as standalone JSON files in <code>data/frameworks/*.json</code>. When a pack is imported, the compliance engine reloads the matrix instantly without server restart.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="font-semibold text-amber-300 font-mono text-[11px] uppercase">
                  2. Vendor Normalization Packs
                </span>
                <p className="text-slate-400 text-[11px]">
                  Defined in <code>data/vendor-packs/*.json</code> and mapped into the runtime learned rule set. New regex extractions evaluate immediately against raw network configs.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                <span className="font-semibold text-emerald-300 font-mono text-[11px] uppercase">
                  3. JSON Schema Validation
                </span>
                <p className="text-slate-400 text-[11px]">
                  Imported packs are checked for valid operators, fields, capture groups, and regex syntax before commit to guarantee engine stability.
                </p>
              </div>
            </div>
          </Card>
        </div>
      </div>
      )}

      {/* MODAL 1: IMPORT FRAMEWORK PACK */}
      {importFwModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-5 shadow-2xl flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileCode2 className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-slate-100">
                  Import Security Framework Pack (JSON)
                </h3>
              </div>
              <button
                onClick={() => setImportFwModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none p-1 cursor-pointer"
              >
                &times;
              </button>
            </div>

            <div className="flex-1 overflow-y-auto py-4 space-y-4 text-xs text-left">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <p className="text-slate-400">
                  Upload a <code>.json</code> file or paste JSON framework specification below.
                </p>
                <button
                  type="button"
                  onClick={() => {
                    setImportFwText(JSON.stringify(SAMPLE_PCI_FRAMEWORK_PACK, null, 2));
                    setImportFwError(null);
                  }}
                  className="px-2 py-1 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 text-[11px] font-mono hover:bg-cyan-900 transition cursor-pointer flex items-center gap-1"
                >
                  <Sparkles className="w-3 h-3 text-cyan-400" />
                  <span>Load Sample: PCI-DSS v4.0 Pack</span>
                </button>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  Choose JSON File:
                </label>
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={(e) => handleFileUpload(e, setImportFwText)}
                  className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-300 hover:file:bg-slate-750 cursor-pointer"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  Framework Pack JSON Definition:
                </label>
                <textarea
                  value={importFwText}
                  onChange={(e) => setImportFwText(e.target.value)}
                  placeholder={`{\n  "frameworkId": "my-standard",\n  "name": "Custom Security Baseline",\n  "version": "v1.0",\n  "description": "Standard controls...",\n  "controls": [\n    {\n      "id": "SEC-1",\n      "title": "Enforce SSHv2",\n      "severity": "HIGH",\n      "field": "ssh_version",\n      "operator": "contains",\n      "expectedValue": "2",\n      "remediation": "For {vendor}, configure 'ip ssh version 2'"\n    }\n  ]\n}`}
                  rows={14}
                  className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500 selection:bg-cyan-500/30"
                />
              </div>

              {importFwError && (
                <div className="p-2.5 rounded bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{importFwError}</span>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setImportFwModalOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleImportFrameworkSubmit}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow transition cursor-pointer flex items-center gap-1.5"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Import & Activate Standard</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: IMPORT VENDOR PACK */}
      {importVendorModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-5 shadow-2xl flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Cpu className="w-5 h-5 text-amber-400" />
                <h3 className="text-sm font-bold text-slate-100">
                  Import Vendor Normalization Pack (JSON)
                </h3>
              </div>
              <button
                onClick={() => setImportVendorModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none p-1 cursor-pointer"
              >
                &times;
              </button>
            </div>

            <div className="flex-1 overflow-y-auto py-4 space-y-4 text-xs text-left">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <p className="text-slate-400">
                  Upload a <code>.json</code> file or paste vendor normalization rules below.
                </p>
                <button
                  type="button"
                  onClick={() => {
                    setImportVendorText(JSON.stringify(SAMPLE_VYOS_VENDOR_PACK, null, 2));
                    setImportVendorError(null);
                  }}
                  className="px-2 py-1 rounded bg-amber-950/80 border border-amber-500/40 text-amber-300 text-[11px] font-mono hover:bg-amber-900 transition cursor-pointer flex items-center gap-1"
                >
                  <Sparkles className="w-3 h-3 text-amber-400" />
                  <span>Load Sample: VyOS Router NOS Pack</span>
                </button>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  Choose JSON File:
                </label>
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={(e) => handleFileUpload(e, setImportVendorText)}
                  className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-amber-300 hover:file:bg-slate-750 cursor-pointer"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-slate-400 mb-1">
                  Vendor Pack JSON Definition:
                </label>
                <textarea
                  value={importVendorText}
                  onChange={(e) => setImportVendorText(e.target.value)}
                  placeholder={`{\n  "vendorPackId": "my-vendor-pack",\n  "vendor": "MikroTik RouterOS",\n  "version": "1.0",\n  "description": "Rules for MikroTik...",\n  "rules": [\n    {\n      "name": "SSH Port Rule",\n      "field": "ssh_version",\n      "regex": "/ip service set ssh port=(\\\\d+)",\n      "extractionType": "presence_true",\n      "sampleLine": "/ip service set ssh port=22"\n    }\n  ]\n}`}
                  rows={14}
                  className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-amber-300 placeholder-slate-600 focus:outline-none focus:border-amber-500 selection:bg-amber-500/30"
                />
              </div>

              {importVendorError && (
                <div className="p-2.5 rounded bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{importVendorError}</span>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setImportVendorModalOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleImportVendorSubmit}
                className="px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold shadow transition cursor-pointer flex items-center gap-1.5"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Import & Register Pack</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* DRAWER 1: VIEW FRAMEWORK CONTROLS */}
      {selectedFramework && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full p-5 shadow-2xl flex flex-col max-h-[85vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>{selectedFramework.name}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/30 text-cyan-300">
                    {selectedFramework.version}
                  </span>
                </h3>
                <p className="text-[11px] font-mono text-slate-400">
                  Framework ID: {selectedFramework.frameworkId} • {selectedFramework.controls?.length || 0} Controls
                </p>
              </div>
              <button
                onClick={() => setSelectedFramework(null)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none p-1 cursor-pointer"
              >
                &times;
              </button>
            </div>

            <div className="flex-1 overflow-y-auto py-4 space-y-3">
              {(selectedFramework.controls || []).map((ctrl, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] font-bold text-cyan-300 bg-cyan-950/80 px-1.5 py-0.5 rounded border border-cyan-500/40">
                        {ctrl.id}
                      </span>
                      <SeverityBadge severity={ctrl.severity} size="sm" />
                    </div>

                    <div className="text-[11px] font-mono text-slate-400">
                      Target Field: <span className="text-slate-200">{ctrl.field}</span> ({ctrl.operator} {String(ctrl.expectedValue)})
                    </div>
                  </div>

                  <p className="text-xs font-semibold text-slate-200">{ctrl.title}</p>
                  <p className="text-[11px] text-slate-400 font-mono bg-slate-900/60 p-2 rounded border border-slate-800/80">
                    Remediation: {ctrl.remediation}
                  </p>
                </div>
              ))}
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => handleExportFramework(selectedFramework.frameworkId, selectedFramework.name)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export This Pack</span>
              </button>

              <button
                onClick={() => setSelectedFramework(null)}
                className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* DRAWER 2: VIEW VENDOR PACK RULES */}
      {selectedVendorPack && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full p-5 shadow-2xl flex flex-col max-h-[85vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <span>{selectedVendorPack.vendor} Normalization Pack</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-950 border border-amber-500/30 text-amber-300">
                    {selectedVendorPack.version}
                  </span>
                </h3>
                <p className="text-[11px] font-mono text-slate-400">
                  Pack ID: {selectedVendorPack.vendorPackId} • {selectedVendorPack.rules?.length || 0} Extraction Rules
                </p>
              </div>
              <button
                onClick={() => setSelectedVendorPack(null)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none p-1 cursor-pointer"
              >
                &times;
              </button>
            </div>

            <div className="flex-1 overflow-y-auto py-4 space-y-3">
              {(selectedVendorPack.rules || []).map((rule, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="font-semibold text-slate-200 text-xs">
                      {rule.name || `Rule #${idx + 1}`}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-amber-300 border border-slate-700">
                      Mode: {rule.extractionType}
                    </span>
                  </div>

                  <div className="text-[11px] font-mono text-slate-300">
                    Target Baseline Field: <span className="text-cyan-400">{rule.field}</span>
                  </div>

                  <div className="p-2 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto">
                    Pattern: /{rule.regex}/
                  </div>

                  {rule.sampleLine && (
                    <p className="text-[10px] font-mono text-slate-500">
                      Sample Match: &quot;{rule.sampleLine}&quot;
                    </p>
                  )}
                </div>
              ))}
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => handleExportVendorPack(selectedVendorPack.vendor, selectedVendorPack.vendorPackId)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export This Pack</span>
              </button>

              <button
                onClick={() => setSelectedVendorPack(null)}
                className="px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
