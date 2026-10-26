import React, { useState } from 'react';
import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Sparkles,
  Terminal,
  FileCode,
  Copy,
  Check,
  RefreshCw,
  Download,
  Search,
  Server,
  Key,
  Lock,
  Globe,
  Radio,
  Clock,
  FileText,
  Cpu,
  Layers,
  HelpCircle,
} from 'lucide-react';
import { NetworkDevice, SecurityBaselineModel } from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';

interface DeviceDetailPageProps {
  device: NetworkDevice;
  onBack: () => void;
  onDeviceUpdated: (updated: NetworkDevice) => void;
}

export function DeviceDetailPage({ device, onBack, onDeviceUpdated }: DeviceDetailPageProps) {
  const { showToast } = useToast();
  const [activeTab, setActiveTab] = useState<'baseline' | 'raw' | 'unrecognized' | 'json'>('baseline');
  const [isRenormalizing, setIsRenormalizing] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [rawSearchQuery, setRawSearchQuery] = useState('');
  const [unrecognizedSearch, setUnrecognizedSearch] = useState('');

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    showToast('Copied', `${label} copied to clipboard`, 'info');
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleDownloadConfig = () => {
    const blob = new Blob([device.rawConfig], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = device.filename;
    link.click();
    URL.revokeObjectURL(url);
    showToast('Downloaded', `Saved ${device.filename}`, 'success');
  };

  const handleDownloadBaselineJson = () => {
    const blob = new Blob([JSON.stringify(device.baselineModel, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${device.hostname || 'device'}-baseline-model.json`;
    link.click();
    URL.revokeObjectURL(url);
    showToast('Exported', 'Security Baseline Model exported as JSON', 'success');
  };

  const handleRenormalize = async () => {
    try {
      setIsRenormalizing(true);
      showToast(
        'Analyzing with Gemini',
        'Re-evaluating unmatched lines and vendor heuristics via Gemini...',
        'info'
      );
      const updated = await apiService.renormalizeDevice(device.id);
      onDeviceUpdated(updated);
      showToast(
        'Normalization Complete',
        `Device baseline model updated. Score: ${updated.overallComplianceScore}%`,
        'success'
      );
    } catch (err: any) {
      showToast(
        'Normalization Failed',
        err.message || 'Failed to re-normalize device config',
        'error'
      );
    } finally {
      setIsRenormalizing(false);
    }
  };

  const b = device.baselineModel;

  // Raw lines with line numbering
  const rawLines = device.rawConfig.split(/\r?\n/);
  const filteredRawLines = rawSearchQuery.trim()
    ? rawLines
        .map((line, idx) => ({ line, num: idx + 1 }))
        .filter((item) => item.line.toLowerCase().includes(rawSearchQuery.toLowerCase()))
    : rawLines.map((line, idx) => ({ line, num: idx + 1 }));

  // Filtered unrecognized lines
  const filteredUnrecognized = unrecognizedSearch.trim()
    ? device.unrecognizedLines.filter(
        (u) =>
          u.line.toLowerCase().includes(unrecognizedSearch.toLowerCase()) ||
          (u.categoryHint && u.categoryHint.toLowerCase().includes(unrecognizedSearch.toLowerCase()))
      )
    : device.unrecognizedLines;

  // Status badge helper
  const getStatusBadge = () => {
    if (device.status === 'COMPLIANT') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
          <ShieldCheck className="w-4 h-4" />
          COMPLIANT ({device.overallComplianceScore}%)
        </span>
      );
    }
    if (device.status === 'WARNING') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40">
          <AlertTriangle className="w-4 h-4" />
          WARNING ({device.overallComplianceScore}%)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40">
        <ShieldAlert className="w-4 h-4" />
        NON-COMPLIANT ({device.overallComplianceScore}%)
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-100 hover:border-slate-700 transition"
            title="Back to Devices list"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <span>NETWORK DEVICES</span>
              <span>/</span>
              <span className="text-slate-300">{device.hostname || device.filename}</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-100 flex items-center gap-3 mt-0.5">
              {device.hostname || 'Unnamed Network Device'}
              {getStatusBadge()}
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRenormalize}
            disabled={isRenormalizing}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium bg-gradient-to-r from-purple-600/30 to-indigo-600/30 hover:from-purple-600/50 hover:to-indigo-600/50 border border-purple-500/40 text-purple-200 transition disabled:opacity-50"
          >
            <Sparkles className={`w-3.5 h-3.5 ${isRenormalizing ? 'animate-spin' : ''}`} />
            {isRenormalizing ? 'Analyzing with Gemini...' : 'Analyze with Gemini'}
          </button>
          <button
            onClick={handleDownloadBaselineJson}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-slate-900 border border-slate-800 text-slate-300 hover:text-slate-100 hover:border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Hardware & Vendor Header Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Vendor Guess Badge */}
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
          <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Detected Vendor / OS</div>
          <div className="mt-1 font-semibold text-sm text-cyan-300 flex items-center gap-1.5 truncate">
            <Cpu className="w-3.5 h-3.5 shrink-0 text-cyan-400" />
            <span className="truncate">{device.detectedVendor}</span>
          </div>
          <div className="mt-1 flex items-center gap-1.5">
            <span
              className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-semibold uppercase ${
                device.vendorGuessMethod === 'regex'
                  ? 'bg-blue-950 text-blue-300 border border-blue-500/30'
                  : device.vendorGuessMethod === 'offline'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                  : 'bg-purple-950 text-purple-300 border border-purple-500/30'
              }`}
            >
              {device.vendorGuessMethod.toUpperCase()} GUESS
            </span>
            <span className="text-[10px] text-slate-400 font-mono">{device.vendorConfidence}% conf</span>
          </div>
        </div>

        {/* Model */}
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
          <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Hardware Model</div>
          <div className="mt-1 font-semibold text-sm text-slate-200 truncate">
            {device.model || 'Unknown Model'}
          </div>
          <div className="mt-1 text-[10px] text-slate-400 font-mono truncate">
            {device.model ? 'Parsed from signature' : 'Not declared in config'}
          </div>
        </div>

        {/* Serial Number */}
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
          <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Serial Number</div>
          <div className="mt-1 font-mono font-medium text-xs text-slate-200 truncate">
            {device.serialNumber || 'N/A'}
          </div>
          <div className="mt-1 text-[10px] text-slate-400 font-mono">
            {device.serialNumber ? 'Chassis Serial' : 'None detected'}
          </div>
        </div>

        {/* File Details */}
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
          <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">File & Size</div>
          <div className="mt-1 font-mono text-xs text-slate-200 truncate">{device.filename}</div>
          <div className="mt-1 text-[10px] text-slate-400 font-mono">
            {device.lineCount} lines ({(device.byteSize / 1024).toFixed(1)} KB)
          </div>
        </div>

        {/* Unrecognized Lines Count */}
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
          <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Unrecognized Lines</div>
          <div className="mt-1 font-semibold text-sm text-amber-300">
            {device.unrecognizedLines.length} line(s)
          </div>
          <div className="mt-1 text-[10px] text-slate-400 font-mono">
            {device.unrecognizedLines.length === 0 ? 'Fully mapped' : 'Pending inspection'}
          </div>
        </div>

        {/* Ingested At */}
        <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
          <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Ingested At</div>
          <div className="mt-1 text-xs text-slate-200 truncate">
            {new Date(device.uploadTime).toLocaleDateString()}
          </div>
          <div className="mt-1 text-[10px] text-slate-400 font-mono truncate">
            {new Date(device.uploadTime).toLocaleTimeString()}
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveTab('baseline')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-medium border-b-2 transition -mb-px ${
            activeTab === 'baseline'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4" />
          Security Baseline Model
        </button>

        <button
          onClick={() => setActiveTab('raw')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-medium border-b-2 transition -mb-px ${
            activeTab === 'raw'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-4 h-4" />
          Raw Configuration ({device.lineCount})
        </button>

        <button
          onClick={() => setActiveTab('unrecognized')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-medium border-b-2 transition -mb-px ${
            activeTab === 'unrecognized'
              ? 'border-amber-400 text-amber-300 bg-amber-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <HelpCircle className="w-4 h-4" />
          Unrecognized Lines
          {device.unrecognizedLines.length > 0 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40">
              {device.unrecognizedLines.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('json')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-medium border-b-2 transition -mb-px ${
            activeTab === 'json'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode className="w-4 h-4" />
          Baseline JSON
        </button>
      </div>

      {/* TAB 1: SECURITY BASELINE MODEL */}
      {activeTab === 'baseline' && (
        <div className="space-y-6">
          {/* Summary Box */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-200">
                  Vendor-Neutral Security Baseline Assessment
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Extracted security controls normalized across Cisco, Juniper, Arista, and Fortinet syntax standards.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <div className="text-right">
                <div className="text-slate-400">Compliance Score</div>
                <div className="text-lg font-bold text-cyan-400">{device.overallComplianceScore}/100</div>
              </div>
              <div className="h-8 w-px bg-slate-800" />
              <div className="text-right">
                <div className="text-slate-400">Baseline Fields</div>
                <div className="text-lg font-bold text-slate-200">15+ Controls</div>
              </div>
            </div>
          </div>

          {/* Baseline Controls Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* 1. SSH Version */}
            <BaselineFieldCard
              title="SSH Version"
              icon={Key}
              value={b.ssh_version.value ? `Version ${b.ssh_version.value}` : 'Disabled / Undefined'}
              isPassing={Boolean(b.ssh_version.value && (b.ssh_version.value.includes('2') || b.ssh_version.value.includes('Strong')))}
              passText="Enforced v2"
              failText={b.ssh_version.value === '1' ? 'Insecure v1' : 'Not Set'}
              field={b.ssh_version}
              onCopySource={() => b.ssh_version.sourceLine && handleCopy(b.ssh_version.sourceLine, 'SSH config line')}
            />

            {/* 2. Telnet Status */}
            <BaselineFieldCard
              title="Telnet Server"
              icon={Terminal}
              value={b.telnet_enabled.value ? 'Enabled (Insecure)' : 'Disabled (Secure)'}
              isPassing={!b.telnet_enabled.value}
              passText="Disabled"
              failText="CRITICAL: Telnet Active"
              field={b.telnet_enabled}
              onCopySource={() => b.telnet_enabled.sourceLine && handleCopy(b.telnet_enabled.sourceLine, 'Telnet config line')}
            />

            {/* 3. HTTP Web Server */}
            <BaselineFieldCard
              title="HTTP Management Server"
              icon={Globe}
              value={b.http_server_enabled.value ? 'Enabled (Cleartext)' : 'Disabled (Secure)'}
              isPassing={!b.http_server_enabled.value}
              passText="Disabled"
              failText="Insecure HTTP Active"
              field={b.http_server_enabled}
              onCopySource={() => b.http_server_enabled.sourceLine && handleCopy(b.http_server_enabled.sourceLine, 'HTTP server line')}
            />

            {/* 4. HTTPS Server */}
            <BaselineFieldCard
              title="HTTPS Secure Server"
              icon={Lock}
              value={b.https_enabled.value ? 'Enabled (Encrypted TLS)' : 'Disabled / Not Configured'}
              isPassing={b.https_enabled.value}
              passText="Enabled"
              failText="Disabled"
              field={b.https_enabled}
              onCopySource={() => b.https_enabled.sourceLine && handleCopy(b.https_enabled.sourceLine, 'HTTPS server line')}
            />

            {/* 5. Password Encryption */}
            <BaselineFieldCard
              title="Password Encryption"
              icon={Lock}
              value={String(b.password_encryption.value)}
              isPassing={
                typeof b.password_encryption.value === 'string' &&
                !b.password_encryption.value.includes('Cleartext') &&
                !b.password_encryption.value.includes('None')
              }
              passText="Encrypted"
              failText="Insecure / Cleartext"
              field={b.password_encryption}
              onCopySource={() => b.password_encryption.sourceLine && handleCopy(b.password_encryption.sourceLine, 'Password encryption line')}
            />

            {/* 6. Min Password Length */}
            <BaselineFieldCard
              title="Minimum Password Length"
              icon={Key}
              value={b.min_password_length.value ? `${b.min_password_length.value} characters` : 'Not Enforced'}
              isPassing={Boolean(b.min_password_length.value && b.min_password_length.value >= 12)}
              passText=">= 12 Characters"
              failText={b.min_password_length.value ? '< 12 Chars' : 'Not Configured'}
              field={b.min_password_length}
              onCopySource={() => b.min_password_length.sourceLine && handleCopy(b.min_password_length.sourceLine, 'Password length line')}
            />

            {/* 7. AAA Authentication */}
            <BaselineFieldCard
              title="AAA Framework"
              icon={ShieldCheck}
              value={b.aaa_enabled.value ? 'Active (new-model / central)' : 'Disabled (Local only)'}
              isPassing={b.aaa_enabled.value}
              passText="Enforced"
              failText="Disabled"
              field={b.aaa_enabled}
              onCopySource={() => b.aaa_enabled.sourceLine && handleCopy(b.aaa_enabled.sourceLine, 'AAA config line')}
            />

            {/* 8. Logging / Syslog Hosts */}
            <BaselineFieldCard
              title="Logging Hosts (Syslog)"
              icon={Server}
              value={
                Array.isArray(b.logging_hosts.value) && b.logging_hosts.value.length > 0
                  ? b.logging_hosts.value.join(', ')
                  : 'No remote syslog hosts configured'
              }
              isPassing={Array.isArray(b.logging_hosts.value) && b.logging_hosts.value.length > 0}
              passText={`${b.logging_hosts.value?.length || 0} Host(s)`}
              failText="None Configured"
              field={b.logging_hosts}
              onCopySource={() => b.logging_hosts.sourceLine && handleCopy(b.logging_hosts.sourceLine, 'Syslog host line')}
            />

            {/* 9. NTP Servers */}
            <BaselineFieldCard
              title="NTP Time Sync Servers"
              icon={Clock}
              value={
                Array.isArray(b.ntp_servers.value) && b.ntp_servers.value.length > 0
                  ? b.ntp_servers.value.join(', ')
                  : 'No NTP servers configured'
              }
              isPassing={Array.isArray(b.ntp_servers.value) && b.ntp_servers.value.length > 0}
              passText={`${b.ntp_servers.value?.length || 0} Server(s)`}
              failText="Unsynchronized"
              field={b.ntp_servers}
              onCopySource={() => b.ntp_servers.sourceLine && handleCopy(b.ntp_servers.sourceLine, 'NTP server line')}
            />

            {/* 10. SNMP Version & Defaults */}
            <BaselineFieldCard
              title="SNMP Configuration"
              icon={Radio}
              value={
                b.snmp_community_default.value
                  ? 'CRITICAL: Insecure default community string (public/private)'
                  : b.snmp_version.value
                  ? `Configured (${b.snmp_version.value})`
                  : 'None / Disabled'
              }
              isPassing={!b.snmp_community_default.value}
              passText={b.snmp_version.value ? 'Secure Community' : 'Disabled'}
              failText="Default Community String"
              field={b.snmp_version}
              onCopySource={() => b.snmp_version.sourceLine && handleCopy(b.snmp_version.sourceLine, 'SNMP config line')}
            />

            {/* 11. Login Banner */}
            <BaselineFieldCard
              title="Warning Login Banner"
              icon={FileText}
              value={b.banner_set.value ? 'Configured (MOTD / Exec)' : 'No Legal Warning Banner Set'}
              isPassing={b.banner_set.value}
              passText="Banner Set"
              failText="Missing Banner"
              field={b.banner_set}
              onCopySource={() => b.banner_set.sourceLine && handleCopy(b.banner_set.sourceLine, 'Banner config line')}
            />

            {/* 12. Session Timeout */}
            <BaselineFieldCard
              title="Session Idle Timeout"
              icon={Clock}
              value={b.session_timeout.value ? `${b.session_timeout.value} minutes` : 'Infinite / Not configured'}
              isPassing={Boolean(b.session_timeout.value && b.session_timeout.value <= 15)}
              passText="<= 15 Minutes"
              failText={b.session_timeout.value ? '> 15 Mins' : 'Unbounded'}
              field={b.session_timeout}
              onCopySource={() => b.session_timeout.sourceLine && handleCopy(b.session_timeout.sourceLine, 'Session timeout line')}
            />

            {/* 13. ACL Rule Count */}
            <BaselineFieldCard
              title="Access Control Lists (ACLs)"
              icon={ShieldCheck}
              value={`${b.acl_count.value} rule set(s) defined`}
              isPassing={b.acl_count.value > 0}
              passText={`${b.acl_count.value} Rules`}
              failText="0 Rules"
              field={b.acl_count}
              onCopySource={() => b.acl_count.sourceLine && handleCopy(b.acl_count.sourceLine, 'ACL line')}
            />

            {/* 14. TLS Min Version */}
            <BaselineFieldCard
              title="TLS Min Protocol Version"
              icon={Lock}
              value={b.tls_min_version.value ? b.tls_min_version.value : 'Default / Unspecified'}
              isPassing={Boolean(b.tls_min_version.value && (b.tls_min_version.value.includes('1.2') || b.tls_min_version.value.includes('1.3')))}
              passText=">= TLS 1.2"
              failText="Legacy TLS Allowed"
              field={b.tls_min_version}
              onCopySource={() => b.tls_min_version.sourceLine && handleCopy(b.tls_min_version.sourceLine, 'TLS version line')}
            />

            {/* 15. Additional Hardening */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300">Hardening Directives</span>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800/40">
                  DEFENSIVE
                </span>
              </div>
              <div className="space-y-1.5 text-[11px] font-mono text-slate-400">
                <div className="flex items-center justify-between">
                  <span>Source Routing Disabled:</span>
                  <span className={b.source_routing_disabled?.value ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                    {b.source_routing_disabled?.value ? 'YES' : 'NO'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>TCP Keepalives In/Out:</span>
                  <span className={b.service_tcp_keepalives?.value ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                    {b.service_tcp_keepalives?.value ? 'YES' : 'NO'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>SSH Timeout:</span>
                  <span className="text-slate-300">{b.ssh_timeout?.value ? `${b.ssh_timeout.value}s` : 'Default'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>SSH Auth Retries:</span>
                  <span className="text-slate-300">{b.ssh_retries?.value ? b.ssh_retries.value : 'Default'}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: RAW CONFIGURATION */}
      {activeTab === 'raw' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/70 p-3 rounded-xl border border-slate-800">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search raw configuration lines..."
                value={rawSearchQuery}
                onChange={(e) => setRawSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleCopy(device.rawConfig, 'Entire config')}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-950 border border-slate-800 text-slate-300 hover:text-slate-100 transition"
              >
                {copiedField === 'Entire config' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                Copy All
              </button>
              <button
                onClick={handleDownloadConfig}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-950 border border-slate-800 text-slate-300 hover:text-slate-100 transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download
              </button>
            </div>
          </div>

          {/* Code Viewer with Monospace and Line Numbers */}
          <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden font-mono text-xs max-h-[600px] overflow-y-auto">
            <div className="bg-slate-900/90 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
                <span className="ml-2 text-slate-300 font-semibold">{device.filename}</span>
              </div>
              <div>
                Showing {filteredRawLines.length} of {rawLines.length} lines
              </div>
            </div>
            <div className="p-4 space-y-0.5 select-text">
              {filteredRawLines.map(({ line, num }) => (
                <div key={num} className="flex items-start hover:bg-slate-900/60 rounded px-1 group">
                  <span className="w-12 shrink-0 text-slate-600 select-none text-right pr-4 group-hover:text-cyan-500">
                    {num}
                  </span>
                  <span
                    className={`whitespace-pre-wrap break-all ${
                      line.trim().startsWith('!') || line.trim().startsWith('#')
                        ? 'text-slate-500 italic'
                        : line.toLowerCase().includes('secret') || line.toLowerCase().includes('password')
                        ? 'text-amber-400'
                        : line.toLowerCase().includes('ssh') || line.toLowerCase().includes('telnet')
                        ? 'text-cyan-300 font-semibold'
                        : line.toLowerCase().includes('logging') || line.toLowerCase().includes('ntp')
                        ? 'text-indigo-300'
                        : 'text-slate-300'
                    }`}
                  >
                    {line || ' '}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: UNRECOGNIZED LINES */}
      {activeTab === 'unrecognized' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <h4 className="text-sm font-semibold text-amber-200 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                {device.unrecognizedLines.length} Unrecognized Line(s) Detected
              </h4>
              <p className="text-xs text-amber-300/80 mt-1 max-w-2xl">
                These lines contain configuration directives not mapped to standard baseline rules. Send these lines to
                Gemini AI to extract additional security baseline controls or confirm vendor-specific policies.
              </p>
            </div>
            <button
              onClick={handleRenormalize}
              disabled={isRenormalizing}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 transition disabled:opacity-50 shrink-0"
            >
              <Sparkles className="w-3.5 h-3.5" />
              {isRenormalizing ? 'Analyzing with Gemini...' : 'Analyze with Gemini'}
            </button>
          </div>

          <div className="flex items-center justify-between gap-3">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Filter unrecognized lines..."
                value={unrecognizedSearch}
                onChange={(e) => setUnrecognizedSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>
            <div className="text-xs text-slate-400 font-mono">
              {filteredUnrecognized.length} matching lines
            </div>
          </div>

          {filteredUnrecognized.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800">
              <Check className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              <h4 className="text-sm font-semibold text-slate-200">No Unrecognized Lines</h4>
              <p className="text-xs text-slate-400 mt-1">
                All lines in this configuration file were recognized by baseline rules or identified as standard network syntax.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80 rounded-xl border border-slate-800 bg-slate-950 overflow-hidden">
              {filteredUnrecognized.map((item, idx) => (
                <div key={idx} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-slate-900/40 transition">
                  <div className="flex items-start gap-3 min-w-0">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700 shrink-0">
                      Line {item.lineNumber}
                    </span>
                    <div className="min-w-0">
                      <div className="font-mono text-xs text-slate-200 break-all">{item.line}</div>
                      {item.categoryHint && (
                        <div className="text-[10px] text-slate-400 mt-0.5 flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-amber-400/80" />
                          Category Hint: {item.categoryHint}
                        </div>
                      )}
                    </div>
                  </div>
                  <button
                    onClick={() => handleCopy(item.line, `Line ${item.lineNumber}`)}
                    className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 shrink-0 self-end sm:self-center"
                    title="Copy line"
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: RAW BASELINE MODEL JSON */}
      {activeTab === 'json' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between bg-slate-900/70 p-3 rounded-xl border border-slate-800">
            <div className="text-xs font-semibold text-slate-300">
              Normalized Security Baseline JSON Representation
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleCopy(JSON.stringify(device.baselineModel, null, 2), 'Baseline JSON')}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-950 border border-slate-800 text-slate-300 hover:text-slate-100 transition"
              >
                {copiedField === 'Baseline JSON' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                Copy JSON
              </button>
              <button
                onClick={handleDownloadBaselineJson}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-950 border border-slate-800 text-slate-300 hover:text-slate-100 transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download JSON
              </button>
            </div>
          </div>

          <pre className="p-4 rounded-xl border border-slate-800 bg-slate-950 text-cyan-300 font-mono text-xs overflow-x-auto max-h-[600px] select-text">
            {JSON.stringify(device.baselineModel, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

// Subcomponent for each baseline field card
interface BaselineFieldCardProps {
  title: string;
  icon: React.ElementType;
  value: string;
  isPassing: boolean;
  passText: string;
  failText: string;
  field: {
    sourceLine?: string | null;
    lineNumber?: number | null;
    confidence: number;
    source?: 'rule' | 'gemini' | 'offline' | 'default';
  };
  onCopySource?: () => void;
}

function BaselineFieldCard({
  title,
  icon: Icon,
  value,
  isPassing,
  passText,
  failText,
  field,
  onCopySource,
}: BaselineFieldCardProps) {
  const confPct = Math.round(field.confidence * 100);

  return (
    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700/80 transition flex flex-col justify-between space-y-3">
      <div>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-400">
            <Icon className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-semibold text-slate-200">{title}</span>
          </div>
          <span
            className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
              isPassing
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/30'
                : 'bg-rose-950/80 text-rose-300 border border-rose-500/30'
            }`}
          >
            {isPassing ? passText : failText}
          </span>
        </div>

        <div className="mt-2 text-sm font-semibold text-slate-100 break-words">{value}</div>
      </div>

      <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono space-y-1.5">
        <div className="flex items-center justify-between text-slate-400">
          <span>Confidence:</span>
          <span className="flex items-center gap-1.5">
            <span
              className={`text-[9px] px-1 rounded uppercase font-semibold ${
                field.source === 'gemini'
                  ? 'bg-purple-950 text-purple-300 border border-purple-500/30'
                  : field.source === 'offline'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                  : 'bg-blue-950 text-blue-300 border border-blue-500/30'
              }`}
            >
              {field.source || 'rule'}
            </span>
            <span className="text-slate-300 font-bold">{confPct}%</span>
          </span>
        </div>

        {field.sourceLine && (
          <div className="flex items-start justify-between gap-1 text-[10px] bg-slate-950/80 p-1.5 rounded border border-slate-800/60 group">
            <span className="text-slate-500 truncate group-hover:text-slate-300" title={field.sourceLine}>
              {field.lineNumber ? `L${field.lineNumber}: ` : ''}
              {field.sourceLine}
            </span>
            {onCopySource && (
              <button
                onClick={onCopySource}
                className="text-slate-500 hover:text-cyan-400 shrink-0"
                title="Copy source line"
              >
                <Copy className="w-3 h-3" />
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
