import React, { useState, useEffect, useMemo } from 'react';
import {
  FileCheck2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  RefreshCw,
  Search,
  Filter,
  ShieldCheck,
  ChevronDown,
  ChevronRight,
  Server,
  Layers,
  Sparkles,
  Download,
  Info,
  SlidersHorizontal,
  ExternalLink,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { SeverityBadge } from '../components/common/Badge';
import {
  SecurityFramework,
  DeviceFrameworkEvaluation,
  NetworkDevice,
  ControlEvaluationResult,
} from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';

export function CompliancePage() {
  const [frameworks, setFrameworks] = useState<SecurityFramework[]>([]);
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [evaluations, setEvaluations] = useState<DeviceFrameworkEvaluation[]>([]);
  const [loading, setLoading] = useState(true);
  const [isEvaluating, setIsEvaluating] = useState(false);

  // Filters & Selection
  const [selectedFrameworkId, setSelectedFrameworkId] = useState<string>('ALL');
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'PASS' | 'FAIL' | 'NOT_EVALUABLE'>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'by-framework' | 'by-device'>('by-framework');

  // Accordion open states
  const [expandedCards, setExpandedCards] = useState<Record<string, boolean>>({});

  const { showToast } = useToast();
  const { hasPermission } = useAuth();

  const loadData = async () => {
    try {
      setLoading(true);
      const [fwList, devList, evalList] = await Promise.all([
        apiService.getComplianceFrameworks(),
        apiService.getDevices(),
        apiService.getComplianceEvaluations(),
      ]);
      setFrameworks(fwList);
      setDevices(devList);
      setEvaluations(evalList);

      // Expand first card by default
      if (evalList.length > 0) {
        setExpandedCards({ [evalList[0].id]: true });
      }
    } catch (err: any) {
      showToast('Error Loading Compliance', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRunEvaluation = async () => {
    try {
      setIsEvaluating(true);
      const fwIds = selectedFrameworkId === 'ALL' ? undefined : [selectedFrameworkId];
      const devIds = selectedDeviceId === 'ALL' ? undefined : [selectedDeviceId];

      const res = await apiService.evaluateCompliance(fwIds, devIds);
      setEvaluations(res.evaluations);

      // Expand all freshly evaluated cards
      const newExpanded: Record<string, boolean> = {};
      res.evaluations.forEach((e) => {
        newExpanded[e.id] = true;
      });
      setExpandedCards(newExpanded);

      showToast(
        'Compliance Evaluation Complete',
        res.message || `Successfully evaluated ${res.evaluations.length} framework matrix results.`,
        'success'
      );
    } catch (err: any) {
      showToast('Evaluation Failed', err.message, 'error');
    } finally {
      setIsEvaluating(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedCards((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // Filtered Evaluations
  const filteredEvaluations = useMemo(() => {
    return evaluations.filter((ev) => {
      if (selectedFrameworkId !== 'ALL' && ev.frameworkId !== selectedFrameworkId) {
        return false;
      }
      if (selectedDeviceId !== 'ALL' && ev.deviceId !== selectedDeviceId) {
        return false;
      }
      return true;
    });
  }, [evaluations, selectedFrameworkId, selectedDeviceId]);

  // Overall aggregate stats across filtered evaluations
  const aggregateStats = useMemo(() => {
    let totalControls = 0;
    let totalPassed = 0;
    let totalFailed = 0;
    let totalNotEvaluable = 0;

    filteredEvaluations.forEach((ev) => {
      totalControls += ev.totalControls;
      totalPassed += ev.passedCount;
      totalFailed += ev.failedCount;
      totalNotEvaluable += ev.notEvaluableCount;
    });

    const evaluable = totalPassed + totalFailed;
    const avgScore = evaluable > 0 ? Math.round((totalPassed / evaluable) * 100) : 0;

    return {
      totalControls,
      totalPassed,
      totalFailed,
      totalNotEvaluable,
      avgScore,
      evalCount: filteredEvaluations.length,
    };
  }, [filteredEvaluations]);

  // Filter controls inside an evaluation
  const filterControlResults = (results: ControlEvaluationResult[]) => {
    return results.filter((c) => {
      if (statusFilter !== 'ALL' && c.status !== statusFilter) return false;
      if (severityFilter !== 'ALL' && c.severity !== severityFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesTitle = c.title.toLowerCase().includes(q);
        const matchesId = c.controlId.toLowerCase().includes(q);
        const matchesField = c.field.toLowerCase().includes(q);
        const matchesRem = c.remediation.toLowerCase().includes(q);
        if (!matchesTitle && !matchesId && !matchesField && !matchesRem) return false;
      }
      return true;
    });
  };

  const exportEvaluationReport = () => {
    const dataStr = JSON.stringify(filteredEvaluations, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `compliance-evaluation-report-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
    showToast('Report Exported', 'Evaluation dataset downloaded as JSON.', 'success');
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <FileCheck2 className="w-6 h-6 text-cyan-400" />
              Compliance Engine
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              Multi-Framework
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Vendor-agnostic baseline policy evaluation engine for CIS, NIST SP 800-53, DISA STIG, and ISO 27001.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={exportEvaluationReport}
            className="px-3 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
          <button
            onClick={handleRunEvaluation}
            disabled={isEvaluating}
            className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg flex items-center gap-2 shadow-lg shadow-cyan-900/30 transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isEvaluating ? 'animate-spin' : ''}`} />
            {isEvaluating ? 'Evaluating Devices...' : 'Run Compliance Evaluation'}
          </button>
        </div>
      </div>

      {/* Aggregate Score & Metrics Card */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Overall Compliance</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className={`text-3xl font-extrabold font-mono ${
              aggregateStats.avgScore >= 80 ? 'text-emerald-400' :
              aggregateStats.avgScore >= 60 ? 'text-amber-400' : 'text-rose-400'
            }`}>
              {aggregateStats.avgScore}%
            </span>
            <span className="text-xs text-slate-400">across fleet</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                aggregateStats.avgScore >= 80 ? 'bg-emerald-500' :
                aggregateStats.avgScore >= 60 ? 'bg-amber-500' : 'bg-rose-500'
              }`}
              style={{ width: `${aggregateStats.avgScore}%` }}
            />
          </div>
        </Card>

        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Controls Passed</span>
          <div className="flex items-center gap-2 mt-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span className="text-2xl font-bold font-mono text-emerald-300">
              {aggregateStats.totalPassed}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2">Verified secure configurations</p>
        </Card>

        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Controls Failed</span>
          <div className="flex items-center gap-2 mt-2">
            <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
            <span className="text-2xl font-bold font-mono text-rose-300">
              {aggregateStats.totalFailed}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2">Remediation action required</p>
        </Card>

        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Not Evaluable</span>
          <div className="flex items-center gap-2 mt-2">
            <HelpCircle className="w-5 h-5 text-amber-400 shrink-0" />
            <span className="text-2xl font-bold font-mono text-amber-300">
              {aggregateStats.totalNotEvaluable}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2">Missing parameter or syntax</p>
        </Card>

        <Card className="p-4 bg-slate-900/80 border-slate-800">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Evaluations Stored</span>
          <div className="flex items-center gap-2 mt-2">
            <Layers className="w-5 h-5 text-cyan-400 shrink-0" />
            <span className="text-2xl font-bold font-mono text-cyan-300">
              {aggregateStats.evalCount}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2">Matrix records active</p>
        </Card>
      </div>

      {/* Selectors & Scope Bar */}
      <Card className="p-4 bg-slate-900/60 border-slate-800 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            {/* Framework Selector */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-400">Framework:</span>
              <select
                value={selectedFrameworkId}
                onChange={(e) => setSelectedFrameworkId(e.target.value)}
                className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Frameworks ({frameworks.length})</option>
                {frameworks.map((fw) => (
                  <option key={fw.frameworkId} value={fw.frameworkId}>
                    {fw.name} ({fw.version})
                  </option>
                ))}
              </select>
            </div>

            {/* Device Selector */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-400">Device:</span>
              <select
                value={selectedDeviceId}
                onChange={(e) => setSelectedDeviceId(e.target.value)}
                className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500 max-w-[220px] truncate"
              >
                <option value="ALL">All Devices ({devices.length})</option>
                {devices.map((dev) => (
                  <option key={dev.id} value={dev.id}>
                    {dev.hostname || dev.filename} ({dev.detectedVendor})
                  </option>
                ))}
              </select>
            </div>

            {/* View Mode Toggle */}
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5">
              <button
                onClick={() => setViewMode('by-framework')}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                  viewMode === 'by-framework'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                By Framework
              </button>
              <button
                onClick={() => setViewMode('by-device')}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                  viewMode === 'by-device'
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/60'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                By Device
              </button>
            </div>
          </div>

          {/* Quick Search & Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search controls, fields, or commands..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 w-56 placeholder:text-slate-600"
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="PASS">Passed Only</option>
              <option value="FAIL">Failed Only</option>
              <option value="NOT_EVALUABLE">Not Evaluable</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        {/* Framework badges quick selector */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/60">
          <span className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mr-1">
            Frameworks:
          </span>
          <button
            onClick={() => setSelectedFrameworkId('ALL')}
            className={`px-2.5 py-1 rounded text-xs transition-colors ${
              selectedFrameworkId === 'ALL'
                ? 'bg-cyan-500 text-slate-950 font-bold'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            All
          </button>
          {frameworks.map((fw) => (
            <button
              key={fw.frameworkId}
              onClick={() => setSelectedFrameworkId(fw.frameworkId)}
              className={`px-2.5 py-1 rounded text-xs transition-colors flex items-center gap-1.5 ${
                selectedFrameworkId === fw.frameworkId
                  ? 'bg-cyan-500 text-slate-950 font-bold'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              <span>{fw.name}</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded ${
                selectedFrameworkId === fw.frameworkId ? 'bg-slate-950 text-cyan-300' : 'bg-slate-900 text-slate-400'
              }`}>
                {fw.controls?.length || 0}
              </span>
            </button>
          ))}
        </div>
      </Card>

      {/* Main Evaluations List */}
      {loading ? (
        <div className="py-20 text-center">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-xs font-mono text-cyan-400">LOADING COMPLIANCE FRAMEWORK MATRIX...</p>
        </div>
      ) : filteredEvaluations.length === 0 ? (
        <Card className="p-12 text-center bg-slate-900/60 border-slate-800">
          <HelpCircle className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-medium text-slate-300">No Evaluation Records Found</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-4">
            No compliance evaluation results match your selected framework or device filter. Click below to run a fresh evaluation across all configurations.
          </p>
          <button
            onClick={handleRunEvaluation}
            className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg inline-flex items-center gap-2"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Evaluate Frameworks Now
          </button>
        </Card>
      ) : (
        <div className="space-y-4">
          {filteredEvaluations.map((ev) => {
            const isExpanded = !!expandedCards[ev.id];
            const filteredControls = filterControlResults(ev.controlResults);

            return (
              <Card
                key={ev.id}
                className="bg-slate-900/90 border-slate-800 overflow-hidden transition-all duration-200"
              >
                {/* Accordion Header */}
                <div
                  onClick={() => toggleExpand(ev.id)}
                  className="p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer hover:bg-slate-800/40 select-none transition-colors border-b border-slate-800/60"
                >
                  <div className="flex items-start md:items-center gap-3">
                    <button
                      type="button"
                      className="p-1 rounded bg-slate-800 text-slate-400 hover:text-white mt-0.5 md:mt-0"
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-cyan-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </button>

                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-slate-100 text-sm tracking-tight">
                          {ev.frameworkName}
                        </span>
                        <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700/60 font-mono">
                          {ev.frameworkVersion}
                        </span>
                        <span className="text-xs text-slate-500">•</span>
                        <div className="flex items-center gap-1.5 text-xs text-cyan-300 font-medium">
                          <Server className="w-3.5 h-3.5 text-cyan-400" />
                          <span>{ev.deviceHostname}</span>
                        </div>
                        <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                          {ev.deviceVendor}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        Evaluated {new Date(ev.evaluatedAt).toLocaleString()}
                      </p>
                    </div>
                  </div>

                  {/* Right side stats pill & score */}
                  <div className="flex items-center gap-4 self-end md:self-center">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/50 text-emerald-400 font-mono">
                        <CheckCircle2 className="w-3 h-3" />
                        {ev.passedCount}
                      </span>
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/50 text-rose-400 font-mono">
                        <XCircle className="w-3 h-3" />
                        {ev.failedCount}
                      </span>
                      {ev.notEvaluableCount > 0 && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/50 text-amber-400 font-mono">
                          <HelpCircle className="w-3 h-3" />
                          {ev.notEvaluableCount}
                        </span>
                      )}
                    </div>

                    <div className="text-right pl-3 border-l border-slate-800">
                      <div className="flex items-baseline gap-1">
                        <span
                          className={`text-xl font-bold font-mono ${
                            ev.complianceScore >= 80
                              ? 'text-emerald-400'
                              : ev.complianceScore >= 60
                              ? 'text-amber-400'
                              : 'text-rose-400'
                          }`}
                        >
                          {ev.complianceScore}%
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500 uppercase font-semibold">
                        Score
                      </span>
                    </div>
                  </div>
                </div>

                {/* Expanded Table of Controls */}
                {isExpanded && (
                  <div className="p-0 overflow-x-auto">
                    {filteredControls.length === 0 ? (
                      <div className="p-8 text-center text-slate-500 text-xs">
                        No controls match the active status or search filters in this framework evaluation.
                      </div>
                    ) : (
                      <table className="w-full text-left text-xs text-slate-300">
                        <thead className="bg-slate-950/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="py-2.5 px-4 font-semibold">Control ID & Title</th>
                            <th className="py-2.5 px-3 font-semibold">Severity</th>
                            <th className="py-2.5 px-3 font-semibold">Status</th>
                            <th className="py-2.5 px-3 font-semibold">Baseline Check</th>
                            <th className="py-2.5 px-4 font-semibold">Detected Value</th>
                            <th className="py-2.5 px-4 font-semibold">Remediation Guide</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/50 font-sans">
                          {filteredControls.map((ctrl) => (
                            <tr
                              key={ctrl.controlId}
                              className={`hover:bg-slate-800/30 transition-colors ${
                                ctrl.status === 'FAIL' ? 'bg-rose-950/10' : ''
                              }`}
                            >
                              {/* Control ID & Title */}
                              <td className="py-3 px-4 max-w-xs">
                                <div className="font-mono text-cyan-400 font-semibold text-[11px]">
                                  {ctrl.controlId}
                                </div>
                                <div className="text-slate-200 font-medium mt-0.5 line-clamp-2">
                                  {ctrl.title}
                                </div>
                              </td>

                              {/* Severity */}
                              <td className="py-3 px-3 whitespace-nowrap">
                                <SeverityBadge severity={ctrl.severity} />
                              </td>

                              {/* Status */}
                              <td className="py-3 px-3 whitespace-nowrap">
                                {ctrl.status === 'PASS' && (
                                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                    <CheckCircle2 className="w-3.5 h-3.5" />
                                    PASS
                                  </span>
                                )}
                                {ctrl.status === 'FAIL' && (
                                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                                    <XCircle className="w-3.5 h-3.5" />
                                    FAIL
                                  </span>
                                )}
                                {ctrl.status === 'NOT_EVALUABLE' && (
                                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                                    <HelpCircle className="w-3.5 h-3.5" />
                                    NOT EVALUABLE
                                  </span>
                                )}
                              </td>

                              {/* Baseline Check */}
                              <td className="py-3 px-3 max-w-[200px]">
                                <span className="font-mono text-[11px] text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                                  {ctrl.field}
                                </span>
                                <div className="text-[11px] text-slate-500 mt-1">
                                  Expected: <span className="text-slate-300 font-mono">{String(ctrl.expectedValue)}</span>
                                </div>
                              </td>

                              {/* Detected Value & Source Line */}
                              <td className="py-3 px-4 max-w-[240px]">
                                <div className="font-mono text-slate-200 text-xs">
                                  {ctrl.actualValue !== null && ctrl.actualValue !== undefined
                                    ? String(ctrl.actualValue)
                                    : 'Not set'}
                                </div>
                                {ctrl.sourceLine && (
                                  <div className="text-[10px] text-slate-400 font-mono bg-slate-950/80 px-1.5 py-0.5 rounded mt-1 border border-slate-800/80 truncate" title={ctrl.sourceLine}>
                                    {ctrl.lineNumber ? `L${ctrl.lineNumber}: ` : ''}{ctrl.sourceLine}
                                  </div>
                                )}
                              </td>

                              {/* Remediation Guide (with vendor substituted) */}
                              <td className="py-3 px-4 max-w-sm">
                                <div className="bg-slate-950/70 p-2 rounded border border-slate-800/80">
                                  <p className="text-[11px] text-slate-300 leading-relaxed font-mono whitespace-pre-wrap selection:bg-cyan-500/40">
                                    {ctrl.remediation}
                                  </p>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
