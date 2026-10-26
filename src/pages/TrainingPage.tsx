import React, { useState, useEffect, useMemo } from 'react';
import {
  GraduationCap,
  Brain,
  Code2,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCw,
  Plus,
  Trash2,
  Search,
  Filter,
  Check,
  X,
  FileCode,
  Server,
  Layers,
  ArrowRight,
  TrendingUp,
  Sliders,
  HelpCircle,
  Eye,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Modal } from '../components/common/Modal';
import {
  LearnedRule,
  TrainingCoverageDiff,
  NetworkDevice,
  SecurityBaselineModel,
} from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';

const BASELINE_FIELD_OPTIONS: Array<{ key: keyof SecurityBaselineModel | string; label: string; desc: string }> = [
  { key: 'ssh_version', label: 'ssh_version', desc: 'SSH protocol version (e.g., "2")' },
  { key: 'telnet_enabled', label: 'telnet_enabled', desc: 'Telnet transport enabled (boolean)' },
  { key: 'http_server_enabled', label: 'http_server_enabled', desc: 'Unencrypted HTTP server active (boolean)' },
  { key: 'https_enabled', label: 'https_enabled', desc: 'Secure HTTPS administration enabled (boolean)' },
  { key: 'password_encryption', label: 'password_encryption', desc: 'Password encryption type (e.g. Type 9, SHA-512)' },
  { key: 'min_password_length', label: 'min_password_length', desc: 'Minimum password character requirement' },
  { key: 'aaa_enabled', label: 'aaa_enabled', desc: 'AAA access control architecture (boolean)' },
  { key: 'logging_hosts', label: 'logging_hosts', desc: 'Remote syslog collector IP / host (array)' },
  { key: 'ntp_servers', label: 'ntp_servers', desc: 'Synchronized network time server (array)' },
  { key: 'snmp_version', label: 'snmp_version', desc: 'SNMP version (e.g., v3 priv)' },
  { key: 'snmp_community_default', label: 'snmp_community_default', desc: 'Default public/private community flag (boolean)' },
  { key: 'banner_set', label: 'banner_set', desc: 'Warning / legal MOTD banner configured (boolean)' },
  { key: 'session_timeout', label: 'session_timeout', desc: 'Inactivity session timeout in minutes' },
  { key: 'acl_count', label: 'acl_count', desc: 'Access control lists configured' },
  { key: 'tls_min_version', label: 'tls_min_version', desc: 'Minimum TLS version (e.g. TLS 1.2)' },
  { key: 'ssh_timeout', label: 'ssh_timeout', desc: 'SSH negotiation timeout in seconds' },
  { key: 'ssh_retries', label: 'ssh_retries', desc: 'SSH authentication maximum retries' },
  { key: 'cdp_lldp_disabled', label: 'cdp_lldp_disabled', desc: 'Discovery protocols disabled (boolean)' },
  { key: 'source_routing_disabled', label: 'source_routing_disabled', desc: 'IP source routing disabled (boolean)' },
  { key: 'service_tcp_keepalives', label: 'service_tcp_keepalives', desc: 'TCP keepalive probing enabled (boolean)' },
];

export function TrainingPage() {
  const [unrecognizedGroups, setUnrecognizedGroups] = useState<
    Array<{
      vendor: string;
      count: number;
      items: Array<{
        line: string;
        lineNumber: number;
        categoryHint?: string;
        deviceId: string;
        deviceHostname: string;
        filename: string;
      }>;
    }>
  >([]);
  const [totalUnrecognized, setTotalUnrecognized] = useState<number>(0);
  const [learnedRules, setLearnedRules] = useState<LearnedRule[]>([]);
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [loading, setLoading] = useState(true);

  // Vendor tab selection
  const [activeVendorTab, setActiveVendorTab] = useState<string>('ALL');

  // Rule Creation Modal State
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [ruleName, setRuleName] = useState('');
  const [ruleVendor, setRuleVendor] = useState('ALL');
  const [ruleField, setRuleField] = useState('session_timeout');
  const [ruleRegex, setRuleRegex] = useState('');
  const [extractionMode, setExtractionMode] = useState<
    'capture_group' | 'presence_true' | 'presence_false' | 'static_value'
  >('capture_group');
  const [captureGroupIndex, setCaptureGroupIndex] = useState(1);
  const [staticValue, setStaticValue] = useState<string>('');
  const [sampleLine, setSampleLine] = useState('');
  const [savingRule, setSavingRule] = useState(false);

  // Live Regex Test Result
  const [regexTestResult, setRegexTestResult] = useState<{
    matches: boolean;
    extractedValue: any;
    error?: string;
  } | null>(null);

  // Re-parse Device State
  const [selectedReparseDeviceId, setSelectedReparseDeviceId] = useState<string>('');
  const [isReparsing, setIsReparsing] = useState(false);
  const [coverageDiff, setCoverageDiff] = useState<TrainingCoverageDiff | null>(null);
  const [isDiffModalOpen, setIsDiffModalOpen] = useState(false);

  // Unrecognized lines search filter
  const [lineSearch, setLineSearch] = useState('');

  const { showToast } = useToast();
  const { user } = useAuth();

  const loadData = async () => {
    try {
      setLoading(true);
      const [unrecRes, rulesRes, devList] = await Promise.all([
        apiService.getTrainingUnrecognizedLines(),
        apiService.getLearnedRules(),
        apiService.getDevices(),
      ]);

      setUnrecognizedGroups(unrecRes.vendorGroups || []);
      setTotalUnrecognized(unrecRes.totalUnrecognized || 0);
      setLearnedRules(rulesRes || []);
      setDevices(devList || []);

      if (devList.length > 0 && !selectedReparseDeviceId) {
        setSelectedReparseDeviceId(devList[0].id);
      }
    } catch (err: any) {
      showToast('Error Loading Training Module', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Update Live Regex Tester whenever inputs change
  useEffect(() => {
    if (!ruleRegex.trim() || !sampleLine.trim()) {
      setRegexTestResult(null);
      return;
    }

    try {
      const reg = new RegExp(ruleRegex, 'i');
      const match = sampleLine.match(reg);

      if (!match) {
        setRegexTestResult({ matches: false, extractedValue: null });
        return;
      }

      let extractedVal: any = true;
      if (extractionMode === 'capture_group') {
        const rawCapture = (match[captureGroupIndex] !== undefined ? match[captureGroupIndex] : match[0]).trim();
        const lower = rawCapture.toLowerCase();
        if (lower === 'enable' || lower === 'enabled' || lower === 'true' || lower === 'yes') {
          extractedVal = true;
        } else if (lower === 'disable' || lower === 'disabled' || lower === 'false' || lower === 'no') {
          extractedVal = false;
        } else if (!isNaN(Number(rawCapture)) && rawCapture !== '') {
          extractedVal = Number(rawCapture);
        } else {
          extractedVal = rawCapture;
        }
      } else if (extractionMode === 'presence_true') {
        extractedVal = true;
      } else if (extractionMode === 'presence_false') {
        extractedVal = false;
      } else if (extractionMode === 'static_value') {
        extractedVal = staticValue;
      }

      setRegexTestResult({ matches: true, extractedValue: extractedVal });
    } catch (err: any) {
      setRegexTestResult({ matches: false, extractedValue: null, error: err.message });
    }
  }, [ruleRegex, sampleLine, extractionMode, captureGroupIndex, staticValue]);

  // Open Training modal pre-filled with an unrecognized line
  const handleTrainLine = (line: string, vendor: string) => {
    setSampleLine(line);
    setRuleVendor(vendor);

    // Heuristic pre-fill suggestions
    let suggestedField = 'session_timeout';
    let suggestedRegex = '';
    let suggestedMode: 'capture_group' | 'presence_true' | 'presence_false' | 'static_value' = 'capture_group';

    const trimmed = line.trim();
    if (/timeout/i.test(trimmed)) {
      suggestedField = 'session_timeout';
      suggestedRegex = trimmed.replace(/\d+/, '(\\d+)');
      suggestedMode = 'capture_group';
    } else if (/ssh/i.test(trimmed)) {
      suggestedField = 'ssh_version';
      suggestedRegex = trimmed.replace(/[12]/, '([12])');
      suggestedMode = 'capture_group';
    } else if (/telnet/i.test(trimmed)) {
      suggestedField = 'telnet_enabled';
      suggestedMode = /no\s+/i.test(trimmed) ? 'presence_false' : 'presence_true';
      suggestedRegex = trimmed;
    } else if (/http/i.test(trimmed)) {
      suggestedField = /https|secure/i.test(trimmed) ? 'https_enabled' : 'http_server_enabled';
      suggestedMode = /no\s+/i.test(trimmed) ? 'presence_false' : 'presence_true';
      suggestedRegex = trimmed;
    } else if (/ntp/i.test(trimmed)) {
      suggestedField = 'ntp_servers';
      suggestedRegex = trimmed.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/, '([0-9.]+)');
      suggestedMode = 'capture_group';
    } else if (/log/i.test(trimmed)) {
      suggestedField = 'logging_hosts';
      suggestedRegex = trimmed.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/, '([0-9.]+)');
      suggestedMode = 'capture_group';
    } else {
      // General regex escape
      suggestedRegex = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      suggestedMode = 'presence_true';
    }

    setRuleField(suggestedField);
    setRuleRegex(suggestedRegex);
    setExtractionMode(suggestedMode);
    setRuleName(`${vendor} ${suggestedField} Rule`);
    setIsCreateModalOpen(true);
  };

  const handleCreateRule = async () => {
    if (!ruleRegex.trim() || !ruleField) {
      showToast('Validation Error', 'Regex pattern and target field are required.', 'error');
      return;
    }

    try {
      setSavingRule(true);
      const created = await apiService.createLearnedRule({
        name: ruleName.trim() || `${ruleVendor} ${ruleField} Extractor`,
        vendor: ruleVendor,
        field: ruleField,
        regex: ruleRegex.trim(),
        extractionMode,
        captureGroupIndex: Number(captureGroupIndex) || 1,
        staticValue: staticValue || null,
        sampleLine,
      });

      setLearnedRules((prev) => [created, ...prev]);
      setIsCreateModalOpen(false);

      showToast(
        'Learned Rule Persisted',
        `Rule [${created.name}] is now live and loaded at runtime without redeploy.`,
        'success'
      );

      // Refresh unrecognized lines and devices
      const unrecRes = await apiService.getTrainingUnrecognizedLines();
      setUnrecognizedGroups(unrecRes.vendorGroups || []);
      setTotalUnrecognized(unrecRes.totalUnrecognized || 0);
    } catch (err: any) {
      showToast('Failed to Create Rule', err.message, 'error');
    } finally {
      setSavingRule(false);
    }
  };

  const handleDeleteRule = async (id: string, name: string) => {
    try {
      await apiService.deleteLearnedRule(id);
      setLearnedRules((prev) => prev.filter((r) => r.id !== id));
      showToast('Rule Deleted', `Removed rule [${name}].`, 'success');
    } catch (err: any) {
      showToast('Deletion Failed', err.message, 'error');
    }
  };

  const handleReparseDevice = async () => {
    if (!selectedReparseDeviceId) {
      showToast('Select a Device', 'Please choose a network device to re-parse.', 'error');
      return;
    }

    try {
      setIsReparsing(true);
      const diff = await apiService.reparseDevice(selectedReparseDeviceId);
      setCoverageDiff(diff);
      setIsDiffModalOpen(true);

      showToast(
        'Device Re-parsed Successfully',
        `Unrecognized lines changed from ${diff.before.unrecognizedCount} to ${diff.after.unrecognizedCount}. Baseline score: ${diff.before.complianceScore}% -> ${diff.after.complianceScore}%.`,
        'success'
      );

      // Refresh overview
      const [unrecRes, devList] = await Promise.all([
        apiService.getTrainingUnrecognizedLines(),
        apiService.getDevices(),
      ]);
      setUnrecognizedGroups(unrecRes.vendorGroups || []);
      setTotalUnrecognized(unrecRes.totalUnrecognized || 0);
      setDevices(devList);
    } catch (err: any) {
      showToast('Re-parsing Failed', err.message, 'error');
    } finally {
      setIsReparsing(false);
    }
  };

  // Filtered Unrecognized Items
  const filteredUnrecognizedLines = useMemo(() => {
    let items: Array<{
      line: string;
      lineNumber: number;
      categoryHint?: string;
      deviceId: string;
      deviceHostname: string;
      filename: string;
      vendor: string;
    }> = [];

    unrecognizedGroups.forEach((group) => {
      if (activeVendorTab === 'ALL' || group.vendor === activeVendorTab) {
        group.items.forEach((item) => {
          items.push({ ...item, vendor: group.vendor });
        });
      }
    });

    if (lineSearch.trim()) {
      const q = lineSearch.toLowerCase().trim();
      items = items.filter(
        (it) =>
          it.line.toLowerCase().includes(q) ||
          it.deviceHostname.toLowerCase().includes(q) ||
          it.vendor.toLowerCase().includes(q)
      );
    }

    return items;
  }, [unrecognizedGroups, activeVendorTab, lineSearch]);

  const allVendors = useMemo(() => {
    return Array.from(new Set(devices.map((d) => d.detectedVendor)));
  }, [devices]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <GraduationCap className="w-6 h-6 text-amber-400" />
              Normalization Training
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
              Runtime Hot-Reload
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Train regex parsing rules on unrecognized network device lines to continuously improve Security Baseline coverage without redeploying.
          </p>
        </div>

        {/* Quick Re-parse Bar */}
        <div className="flex items-center gap-2 bg-slate-900 p-2 rounded-xl border border-slate-800">
          <select
            value={selectedReparseDeviceId}
            onChange={(e) => setSelectedReparseDeviceId(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-amber-500 max-w-[200px] truncate"
          >
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.hostname || d.filename} ({d.detectedVendor})
              </option>
            ))}
          </select>
          <button
            onClick={handleReparseDevice}
            disabled={isReparsing || !selectedReparseDeviceId}
            className="px-3.5 py-1.5 text-xs font-semibold bg-amber-600 hover:bg-amber-500 text-slate-950 rounded-lg flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RotateCw className={`w-3.5 h-3.5 ${isReparsing ? 'animate-spin' : ''}`} />
            {isReparsing ? 'Re-parsing...' : 'Re-parse Device'}
          </button>
        </div>
      </div>

      {/* Overview Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Unrecognized Lines</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-amber-400">
              {totalUnrecognized}
            </span>
            <span className="text-xs text-slate-500">across fleet</span>
          </div>
          <p className="text-xs text-slate-500 mt-2">Lines requiring training patterns</p>
        </Card>

        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Learned Rules</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-cyan-400">
              {learnedRules.length}
            </span>
            <span className="text-xs text-slate-500">rules active</span>
          </div>
          <p className="text-xs text-slate-500 mt-2">Hot-loaded into parser memory</p>
        </Card>

        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Monitored Vendors</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-purple-400">
              {unrecognizedGroups.length}
            </span>
            <span className="text-xs text-slate-500">unique vendors</span>
          </div>
          <p className="text-xs text-slate-500 mt-2">With vendor-specific syntax</p>
        </Card>

        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Engine Status</span>
          <div className="flex items-center gap-2 mt-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span className="text-lg font-bold font-mono text-emerald-300">
              HOT RELOAD READY
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2">Zero-redeploy runtime execution</p>
        </Card>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Unrecognized Lines Grouped by Vendor (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          <Card className="p-5 bg-slate-900/90 border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div>
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-amber-400" />
                  Unrecognized Configuration Lines
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Lines that did not match core baseline patterns. Click "Train Rule" to teach the engine.
                </p>
              </div>

              {/* Search */}
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search lines..."
                  value={lineSearch}
                  onChange={(e) => setLineSearch(e.target.value)}
                  className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-amber-500 w-44 placeholder:text-slate-600"
                />
              </div>
            </div>

            {/* Vendor Filter Tabs */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-2 border-b border-slate-800">
              <button
                onClick={() => setActiveVendorTab('ALL')}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors shrink-0 ${
                  activeVendorTab === 'ALL'
                    ? 'bg-amber-500 text-slate-950 font-bold'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                All Vendors ({totalUnrecognized})
              </button>
              {unrecognizedGroups.map((g) => (
                <button
                  key={g.vendor}
                  onClick={() => setActiveVendorTab(g.vendor)}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors shrink-0 flex items-center gap-1.5 ${
                    activeVendorTab === g.vendor
                      ? 'bg-amber-500 text-slate-950 font-bold'
                      : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <span>{g.vendor}</span>
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                      activeVendorTab === g.vendor ? 'bg-slate-950 text-amber-300' : 'bg-slate-900 text-slate-400'
                    }`}
                  >
                    {g.count}
                  </span>
                </button>
              ))}
            </div>

            {/* Lines List */}
            <div className="mt-4 space-y-2 max-h-[550px] overflow-y-auto pr-1">
              {filteredUnrecognizedLines.length === 0 ? (
                <div className="py-12 text-center text-slate-500 text-xs">
                  <CheckCircle2 className="w-8 h-8 text-emerald-500/60 mx-auto mb-2" />
                  No unrecognized lines found! All configuration statements are parsed by baseline or learned rules.
                </div>
              ) : (
                filteredUnrecognizedLines.map((item, idx) => (
                  <div
                    key={`${item.deviceId}-${item.lineNumber}-${idx}`}
                    className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg hover:border-slate-700 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 text-[11px] text-slate-400 mb-1 flex-wrap">
                        <span className="font-mono text-cyan-400">
                          {item.deviceHostname}
                        </span>
                        <span>•</span>
                        <span className="text-slate-500 font-mono text-[10px]">
                          L{item.lineNumber}
                        </span>
                        <span>•</span>
                        <span className="px-1.5 py-0.2 rounded bg-slate-900 text-amber-300 border border-amber-900/50 text-[10px]">
                          {item.vendor}
                        </span>
                      </div>
                      <div className="font-mono text-xs text-slate-200 bg-slate-900/90 px-2 py-1 rounded border border-slate-800/60 break-all select-all">
                        {item.line}
                      </div>
                    </div>

                    <button
                      onClick={() => handleTrainLine(item.line, item.vendor)}
                      className="px-3 py-1.5 text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500 hover:text-slate-950 rounded-lg shrink-0 flex items-center gap-1.5 transition-colors"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      Train Rule
                    </button>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>

        {/* Right Column: Active Learned Rules (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          <Card className="p-5 bg-slate-900/90 border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Brain className="w-4 h-4 text-cyan-400" />
                  Active Learned Rules ({learnedRules.length})
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Runtime patterns dynamically evaluated during normalization.
                </p>
              </div>

              <button
                onClick={() => {
                  setSampleLine('');
                  setRuleName('');
                  setRuleRegex('');
                  setRuleVendor(allVendors[0] || 'ALL');
                  setRuleField('session_timeout');
                  setExtractionMode('capture_group');
                  setIsCreateModalOpen(true);
                }}
                className="px-2.5 py-1 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-1 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                New Rule
              </button>
            </div>

            <div className="space-y-3 max-h-[550px] overflow-y-auto pr-1">
              {learnedRules.length === 0 ? (
                <div className="py-12 text-center text-slate-500 text-xs">
                  No learned rules configured yet. Train unrecognized lines from the left pane.
                </div>
              ) : (
                learnedRules.map((rule) => (
                  <div
                    key={rule.id}
                    className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-2 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="font-semibold text-xs text-slate-100">
                          {rule.name}
                        </div>
                        <div className="flex items-center gap-1.5 text-[11px] text-slate-400 mt-0.5">
                          <span className="text-amber-400 font-medium">{rule.vendor}</span>
                          <span>•</span>
                          <span className="font-mono text-cyan-400">{rule.field}</span>
                        </div>
                      </div>

                      <button
                        onClick={() => handleDeleteRule(rule.id, rule.name)}
                        className="text-slate-500 hover:text-rose-400 p-1 rounded transition-colors"
                        title="Delete rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="bg-slate-900/90 p-1.5 rounded border border-slate-800 font-mono text-[11px] text-cyan-300 break-all select-all">
                      {rule.regex}
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-800/60">
                      <span className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-300 font-mono">
                        Mode: {rule.extractionType}
                      </span>
                      <span>By {rule.createdBy}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      </div>

      {/* Train / Create Rule Modal */}
      {isCreateModalOpen && (
        <Modal
          isOpen={isCreateModalOpen}
          onClose={() => setIsCreateModalOpen(false)}
          title="Create Normalization Learning Rule"
          maxWidth="2xl"
        >
          <div className="space-y-4">
            <p className="text-xs text-slate-400">
              Configure a regex extractor that parses vendor-specific syntax into a vendor-neutral Security Baseline Model parameter.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Rule Name */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Rule Name
                </label>
                <input
                  type="text"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  placeholder="e.g. Fortinet Admin Idle Timeout Extractor"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>

              {/* Vendor */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Target Vendor
                </label>
                <select
                  value={ruleVendor}
                  onChange={(e) => setRuleVendor(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                >
                  <option value="ALL">ALL (Universal Pattern)</option>
                  {allVendors.map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Target Baseline Field */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Target Baseline Model Field
              </label>
              <select
                value={ruleField}
                onChange={(e) => setRuleField(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
              >
                {BASELINE_FIELD_OPTIONS.map((f) => (
                  <option key={f.key} value={f.key}>
                    {f.label} — {f.desc}
                  </option>
                ))}
              </select>
            </div>

            {/* Extraction Mode */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Value Extraction Mode
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <button
                  type="button"
                  onClick={() => setExtractionMode('capture_group')}
                  className={`p-2 rounded-lg text-xs font-medium text-left border transition-colors ${
                    extractionMode === 'capture_group'
                      ? 'bg-amber-950/60 border-amber-500 text-amber-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="font-semibold">Capture Group</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Regex (group 1)</div>
                </button>

                <button
                  type="button"
                  onClick={() => setExtractionMode('presence_true')}
                  className={`p-2 rounded-lg text-xs font-medium text-left border transition-colors ${
                    extractionMode === 'presence_true'
                      ? 'bg-amber-950/60 border-amber-500 text-amber-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="font-semibold">Presence True</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Matched = true</div>
                </button>

                <button
                  type="button"
                  onClick={() => setExtractionMode('presence_false')}
                  className={`p-2 rounded-lg text-xs font-medium text-left border transition-colors ${
                    extractionMode === 'presence_false'
                      ? 'bg-amber-950/60 border-amber-500 text-amber-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="font-semibold">Presence False</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Matched = false</div>
                </button>

                <button
                  type="button"
                  onClick={() => setExtractionMode('static_value')}
                  className={`p-2 rounded-lg text-xs font-medium text-left border transition-colors ${
                    extractionMode === 'static_value'
                      ? 'bg-amber-950/60 border-amber-500 text-amber-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="font-semibold">Static Value</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Custom fixed value</div>
                </button>
              </div>
            </div>

            {/* Extra options for extraction mode */}
            {extractionMode === 'capture_group' && (
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Capture Group Index
                </label>
                <input
                  type="number"
                  min={1}
                  max={5}
                  value={captureGroupIndex}
                  onChange={(e) => setCaptureGroupIndex(Number(e.target.value))}
                  className="w-24 bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                />
                <span className="text-[11px] text-slate-500 ml-2">
                  (Index 1 corresponds to first parentheses pair)
                </span>
              </div>
            )}

            {extractionMode === 'static_value' && (
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Static Value to Assign
                </label>
                <input
                  type="text"
                  value={staticValue}
                  onChange={(e) => setStaticValue(e.target.value)}
                  placeholder="e.g. Type 9 (Scrypt) or TLS 1.3"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
                />
              </div>
            )}

            {/* Regex Pattern */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Regular Expression (Case-Insensitive)
              </label>
              <input
                type="text"
                value={ruleRegex}
                onChange={(e) => setRuleRegex(e.target.value)}
                placeholder="e.g. set\s+admintimeout\s+(\d+)"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-amber-500"
              />
            </div>

            {/* Sample Line for Live Testing */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Sample Config Line (Test Sandbox)
              </label>
              <input
                type="text"
                value={sampleLine}
                onChange={(e) => setSampleLine(e.target.value)}
                placeholder="e.g. set admintimeout 10"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500"
              />
            </div>

            {/* Live Sandbox Test Result */}
            {regexTestResult && (
              <div
                className={`p-3 rounded-lg border text-xs flex items-center justify-between gap-3 ${
                  regexTestResult.matches
                    ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                    : 'bg-rose-950/40 border-rose-800 text-rose-300'
                }`}
              >
                <div className="flex items-center gap-2">
                  {regexTestResult.matches ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                  )}
                  <span>
                    {regexTestResult.matches
                      ? `Matches successfully! Extracted value: ${JSON.stringify(regexTestResult.extractedValue)}`
                      : regexTestResult.error
                      ? `Regex Syntax Error: ${regexTestResult.error}`
                      : 'Pattern does not match sample line.'}
                  </span>
                </div>
                {regexTestResult.matches && (
                  <span className="font-mono text-[10px] bg-emerald-900/60 px-2 py-0.5 rounded text-emerald-200">
                    Target: {ruleField} = {String(regexTestResult.extractedValue)}
                  </span>
                )}
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(false)}
                className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleCreateRule}
                disabled={Boolean(savingRule || (regexTestResult && !regexTestResult.matches && !!sampleLine))}
                className="px-4 py-2 text-xs font-semibold bg-amber-600 hover:bg-amber-500 text-slate-950 rounded-lg flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Check className="w-4 h-4" />
                {savingRule ? 'Saving Rule...' : 'Save Learned Rule'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Coverage Diff Modal */}
      {isDiffModalOpen && coverageDiff && (
        <Modal
          isOpen={isDiffModalOpen}
          onClose={() => setIsDiffModalOpen(false)}
          title={`Before / After Coverage Analysis: ${coverageDiff.deviceHostname}`}
          maxWidth="2xl"
        >
          <div className="space-y-5">
            <p className="text-xs text-slate-400">
              Detailed breakdown of parser coverage improvement resulting from newly learned normalization rules.
            </p>

            {/* Comparison Metrics */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Unrecognized Lines
                </span>
                <div className="flex items-center gap-3 mt-2">
                  <span className="text-2xl font-bold font-mono text-slate-400">
                    {coverageDiff.before.unrecognizedCount}
                  </span>
                  <ArrowRight className="w-4 h-4 text-slate-500" />
                  <span className="text-2xl font-bold font-mono text-emerald-400">
                    {coverageDiff.after.unrecognizedCount}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300 font-mono">
                    -{coverageDiff.before.unrecognizedCount - coverageDiff.after.unrecognizedCount} lines resolved!
                  </span>
                </div>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Baseline Compliance Score
                </span>
                <div className="flex items-center gap-3 mt-2">
                  <span className="text-2xl font-bold font-mono text-slate-400">
                    {coverageDiff.before.complianceScore}%
                  </span>
                  <ArrowRight className="w-4 h-4 text-slate-500" />
                  <span className="text-2xl font-bold font-mono text-cyan-400">
                    {coverageDiff.after.complianceScore}%
                  </span>
                  {coverageDiff.after.complianceScore > coverageDiff.before.complianceScore && (
                    <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono">
                      +{coverageDiff.after.complianceScore - coverageDiff.before.complianceScore}%
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Resolved Lines List */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Newly Recognized Statements ({coverageDiff.remediatedLines.length})
              </h4>
              {coverageDiff.remediatedLines.length === 0 ? (
                <div className="p-4 bg-slate-950 rounded-lg text-slate-500 text-xs text-center">
                  No previously unrecognized lines were resolved on this device by the current rule set.
                </div>
              ) : (
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {coverageDiff.remediatedLines.map((rem, i) => (
                    <div
                      key={i}
                      className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-semibold text-cyan-300">{rem.ruleName}</span>
                        <span className="text-slate-400 font-mono">L{rem.lineNumber}</span>
                      </div>
                      <div className="font-mono text-slate-200 bg-slate-900 p-1.5 rounded border border-slate-800 text-[11px]">
                        {rem.line}
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-emerald-400 pt-0.5">
                        <Check className="w-3 h-3" />
                        <span>
                          Mapped to <span className="font-mono font-bold">{rem.targetField}</span> ={' '}
                          <span className="font-mono">{JSON.stringify(rem.extractedValue)}</span>
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setIsDiffModalOpen(false)}
                className="px-4 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors"
              >
                Close Summary
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
