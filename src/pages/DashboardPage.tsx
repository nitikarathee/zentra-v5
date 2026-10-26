import React, { useState, useEffect } from 'react';
import {
  Cpu,
  FileCheck2,
  GraduationCap,
  FileText,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  TrendingUp,
  RefreshCw,
  ExternalLink,
  Layers,
  Database,
  Terminal,
  Server,
  Zap,
  Archive,
  Download,
} from 'lucide-react';
import JSZip from 'jszip';
import { MetricCard } from '../components/common/MetricCard';
import { Card } from '../components/common/Card';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { DashboardStats, NetworkDevice } from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';

interface DashboardPageProps {
  onNavigateTab: (tab: string) => void;
  onSelectFinding?: (id: string) => void;
  // Optional legacy props to maintain backwards compatibility
  onSelectApi?: (id: string) => void;
  onOpenScanModal?: () => void;
}

export function DashboardPage({
  onNavigateTab,
  onSelectFinding,
}: DashboardPageProps) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [isAuditing, setIsAuditing] = useState(false);
  const [isLoadingSamples, setIsLoadingSamples] = useState(false);
  const { showToast } = useToast();

  const loadData = async () => {
    try {
      setLoading(true);
      const [statsData, devicesData] = await Promise.all([
        apiService.getDashboardStats(),
        apiService.getDevices(),
      ]);
      setStats(statsData);
      setDevices(devicesData);
    } catch (err: any) {
      showToast('Failed to load dashboard data', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleLoadSamples = async () => {
    try {
      setIsLoadingSamples(true);
      showToast('Ingesting Sample Fleet...', 'Loading Cisco, Palo Alto, Juniper, Arista, and SONiC configs', 'info');
      const res = await apiService.loadSampleDevices();
      await loadData();
      showToast('Sample Fleet Loaded', `Ingested ${res.devices?.length || 5} vendor configurations & evaluated compliance matrix.`, 'success');
    } catch (err: any) {
      showToast('Failed to load samples', err.message, 'error');
    } finally {
      setIsLoadingSamples(false);
    }
  };

  const handleRunFullEvaluation = async () => {
    try {
      setIsAuditing(true);
      showToast('Running Full Compliance Evaluation...', 'Evaluating all devices against CIS, NIST, DISA STIG, and ISO 27001', 'info');
      await apiService.evaluateCompliance();
      await loadData();
    } catch (err: any) {
      showToast('Evaluation failed', err.message, 'error');
    } finally {
      setIsAuditing(false);
    }
  };

  const [isExportingBundle, setIsExportingBundle] = useState(false);

  const handleExportSecurityBundleZip = async () => {
    try {
      setIsExportingBundle(true);
      showToast('Compiling Security Archive...', 'Packaging active Zero-Trust posture, CIS controls, findings, and network fleet into ZIP.', 'info');
      const [findings, compliance, zeroTrust, statData, devList] = await Promise.all([
        apiService.getFindings().catch(() => []),
        apiService.getCompliance().catch(() => null),
        apiService.getZeroTrust().catch(() => null),
        apiService.getDashboardStats().catch(() => stats),
        apiService.getDevices().catch(() => devices),
      ]);

      const zip = new JSZip();

      // 1. Dashboard summary
      zip.file('dashboard-metrics.json', JSON.stringify(statData?.metrics || {}, null, 2));

      // 2. Active findings
      zip.file('security-findings.json', JSON.stringify(findings, null, 2));

      // 3. CIS Controls
      if (compliance?.controls) {
        zip.file('cis-compliance-controls.json', JSON.stringify(compliance.controls, null, 2));
      }

      // 4. Zero-Trust evaluation
      if (zeroTrust) {
        zip.file('zero-trust-assessment.json', JSON.stringify(zeroTrust, null, 2));
      }

      // 5. Network devices fleet status
      zip.file('network-fleet-devices.json', JSON.stringify(devList, null, 2));

      // 6. Manifest
      const manifest = {
        archive: 'ZENTRA Enterprise Zero-Trust & Network Compliance Snapshot',
        exportedAt: new Date().toISOString(),
        summary: {
          totalApis: statData?.metrics?.totalApis,
          zeroTrustScore: statData?.metrics?.zeroTrustScore,
          complianceScore: statData?.metrics?.complianceScore,
          openFindings: findings.length,
          networkDevices: devList.length,
        },
      };
      zip.file('audit-manifest.json', JSON.stringify(manifest, null, 2));

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `zentra-security-bundle-${new Date().toISOString().split('T')[0]}.zip`;
      a.click();
      URL.revokeObjectURL(url);

      showToast('ZIP Bundle Downloaded', 'Exported complete security & compliance snapshot archive.', 'success');
    } catch (err: any) {
      showToast('Export Error', err.message, 'error');
    } finally {
      setIsExportingBundle(false);
    }
  };

  if (loading || !stats) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-sm font-mono text-slate-400">Loading Network Security & Compliance Dashboard...</p>
      </div>
    );
  }

  const { metrics, fleet } = stats;

  const totalDevices = fleet?.totalDevices ?? devices.length;
  const avgCompliance = fleet?.avgFleetCompliance ?? metrics.complianceScore ?? 0;
  const compliantCount = fleet?.compliantDevices ?? devices.filter((d) => (d.complianceScore ?? d.overallComplianceScore ?? 0) >= 80).length;
  const warningCount = fleet?.warningDevices ?? devices.filter((d) => (d.complianceScore ?? d.overallComplianceScore ?? 0) >= 50 && (d.complianceScore ?? d.overallComplianceScore ?? 0) < 80).length;
  const nonCompliantCount = fleet?.nonCompliantDevices ?? devices.filter((d) => (d.complianceScore ?? d.overallComplianceScore ?? 0) < 50).length;
  const unrecognizedLinesCount = fleet?.unrecognizedLinesCount ?? devices.reduce((acc, d) => acc + (d.unrecognizedLines?.length || 0), 0);
  const learnedRulesCount = fleet?.learnedRulesCount ?? 0;
  const totalControls = fleet?.totalControlsEvaluated ?? (metrics.passedControls + metrics.failedControls);
  const passedControls = fleet?.passedControls ?? metrics.passedControls;
  const failedControls = fleet?.failedControls ?? metrics.failedControls;

  return (
    <div className="space-y-6 text-left">
      {/* Top Banner & Quick Actions */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/30 backdrop-blur-md shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 border border-cyan-500/40 text-cyan-300">
              NETSEC COMPLIANCE ENGINE v3.2
            </span>
            <span className="text-xs text-slate-400">• Multi-Vendor Security Baseline Governance</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight mt-1">
            Network Device Security Baseline & Compliance
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Automated configuration normalization, 4-framework compliance evaluation (CIS, NIST SP 800-53, DISA STIG, ISO 27001), and vendor CLI remediation.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            onClick={handleLoadSamples}
            disabled={isLoadingSamples}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition active:scale-95 disabled:opacity-60 cursor-pointer"
            title="Load 5 realistic network configurations: Cisco, Palo Alto, Juniper, Arista, and SONiC"
          >
            <Database className={`w-3.5 h-3.5 ${isLoadingSamples ? 'animate-spin' : ''}`} />
            <span>{isLoadingSamples ? 'Loading Fleet...' : 'Load Sample Fleet (5 Vendors)'}</span>
          </button>

          <button
            onClick={handleRunFullEvaluation}
            disabled={isAuditing}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-800 text-slate-200 text-xs font-semibold transition active:scale-95 disabled:opacity-60 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isAuditing ? 'animate-spin text-cyan-400' : ''}`} />
            <span>{isAuditing ? 'Evaluating...' : 'Run Audit Evaluation'}</span>
          </button>

          <button
            onClick={handleExportSecurityBundleZip}
            disabled={isExportingBundle}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-purple-500/40 bg-purple-950/50 hover:bg-purple-900/50 text-purple-200 text-xs font-semibold transition active:scale-95 disabled:opacity-60 cursor-pointer shadow-lg shadow-purple-900/20"
            title="Download full JSON snapshot of Zero-Trust posture, findings, CIS controls, and network fleet in a ZIP archive"
          >
            <Archive className={`w-3.5 h-3.5 text-purple-400 ${isExportingBundle ? 'animate-bounce' : ''}`} />
            <span>{isExportingBundle ? 'Packaging ZIP...' : 'Security Bundle (.zip)'}</span>
          </button>

          <button
            onClick={() => onNavigateTab('scanner')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-cyan-500/40 bg-cyan-950/50 hover:bg-cyan-900/50 text-cyan-200 text-xs font-semibold transition active:scale-95 cursor-pointer shadow-lg shadow-cyan-900/20"
            title="Scan OpenAPI specification or ZIP collection"
          >
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>Scan API / ZIP Spec</span>
          </button>

          <button
            onClick={() => onNavigateTab('reports')}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg border border-indigo-500/30 bg-indigo-950/40 hover:bg-indigo-900/40 text-indigo-300 text-xs font-semibold transition active:scale-95 cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5 text-indigo-400" />
            <span>Audit Reports & ZIP</span>
          </button>
        </div>
      </div>

      {/* Zero-Trust & API Security Posture Strip ("The Old One") */}
      <div>
        <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center justify-between mb-2.5">
          <div className="flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>Zero-Trust API Security & Identity Posture</span>
          </div>
          <span className="text-[10px] text-cyan-400 font-mono">NIST SP 800-207 Architecture</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          <MetricCard
            title="Monitored APIs"
            value={metrics.totalApis}
            subtitle={`${metrics.activeApis} active services`}
            icon={Server}
            variant="cyan"
            onClick={() => onNavigateTab('apis')}
          />
          <MetricCard
            title="Zero-Trust Score"
            value={`${metrics.zeroTrustScore}%`}
            subtitle="Continuous verification"
            change={metrics.zeroTrustScore >= 75 ? 'OPTIMAL' : 'IMPROVE'}
            trend={metrics.zeroTrustScore >= 75 ? 'up' : 'down'}
            icon={ShieldCheck}
            variant="emerald"
            onClick={() => onNavigateTab('zero-trust')}
          />
          <MetricCard
            title="CIS Benchmark"
            value={`${metrics.complianceScore}%`}
            subtitle={`${metrics.passedControls} passed / ${metrics.failedControls} failed`}
            icon={FileCheck2}
            variant="blue"
            onClick={() => onNavigateTab('compliance')}
          />
          <MetricCard
            title="Critical Findings"
            value={metrics.criticalVulnerabilities}
            subtitle={`${metrics.highVulnerabilities} High / ${metrics.mediumVulnerabilities} Medium`}
            change={metrics.criticalVulnerabilities > 0 ? 'URGENT' : 'NONE'}
            trend={metrics.criticalVulnerabilities > 0 ? 'down' : 'up'}
            icon={ShieldAlert}
            variant="rose"
            onClick={() => onNavigateTab('findings')}
          />
        </div>
      </div>

      {/* Network Configuration Fleet Strip */}
      <div>
        <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center justify-between mb-2.5">
          <div className="flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Network Device Security Baseline & Compliance</span>
          </div>
          <span className="text-[10px] text-emerald-400 font-mono">4-Framework Standards (CIS/NIST/STIG/ISO)</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-3 sm:gap-4">
          <MetricCard
            title="Monitored Devices"
            value={totalDevices}
            subtitle="Multi-vendor fleet"
            icon={Cpu}
            variant="cyan"
            onClick={() => onNavigateTab('devices')}
          />

        <MetricCard
          title="Fleet Compliance"
          value={`${avgCompliance}%`}
          subtitle="Weighted baseline score"
          change={avgCompliance >= 75 ? 'STABLE' : 'ACTION NEEDED'}
          trend={avgCompliance >= 75 ? 'up' : 'down'}
          icon={ShieldCheck}
          variant="emerald"
          onClick={() => onNavigateTab('compliance')}
        />

        <MetricCard
          title="Compliant (>=80%)"
          value={compliantCount}
          subtitle="Meets all strict baselines"
          icon={ShieldCheck}
          variant="emerald"
          onClick={() => onNavigateTab('devices')}
        />

        <MetricCard
          title="Warning (50-79%)"
          value={warningCount}
          subtitle="Minor control gaps"
          icon={AlertTriangle}
          variant="amber"
          onClick={() => onNavigateTab('devices')}
        />

        <MetricCard
          title="Non-Compliant (<50%)"
          value={nonCompliantCount}
          subtitle="Critical remediation queue"
          change={nonCompliantCount > 0 ? 'URGENT' : 'NONE'}
          trend={nonCompliantCount > 0 ? 'down' : 'up'}
          icon={ShieldAlert}
          variant="rose"
          onClick={() => onNavigateTab('devices')}
        />

        <MetricCard
          title="Controls Evaluated"
          value={totalControls}
          subtitle={`${passedControls} passed / ${failedControls} failed`}
          icon={FileCheck2}
          variant="blue"
          onClick={() => onNavigateTab('compliance')}
        />

        <MetricCard
          title="Parser Health"
          value={unrecognizedLinesCount}
          subtitle={`${learnedRulesCount} active learned rules`}
          change={unrecognizedLinesCount > 0 ? 'NEEDS TRAINING' : 'OPTIMAL'}
          trend={unrecognizedLinesCount > 0 ? 'down' : 'up'}
          icon={GraduationCap}
          variant="purple"
          onClick={() => onNavigateTab('training')}
        />
      </div>
    </div>

      {/* Framework Compliance Matrix & Vendor Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: Multi-Framework Governance Matrix */}
        <Card
          title="Multi-Framework Compliance Matrix"
          subtitle="JSON-defined standards evaluated against baseline models"
          action={
            <button
              onClick={() => onNavigateTab('compliance')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
            >
              <span>Full Matrix</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          }
        >
          <div className="space-y-4 pt-1">
            {(fleet?.frameworkSummaries && fleet.frameworkSummaries.length > 0
              ? fleet.frameworkSummaries
              : [
                  { id: 'cis', name: 'CIS Network Devices Benchmark', version: 'v3.0.0', avgScore: 82, passCount: 18, failCount: 4, notEvalCount: 0 },
                  { id: 'nist_800_53', name: 'NIST SP 800-53 Rev 5', version: 'Rev 5', avgScore: 78, passCount: 16, failCount: 5, notEvalCount: 1 },
                  { id: 'disa_stig', name: 'DISA STIG Network Device', version: 'V2R3', avgScore: 73, passCount: 14, failCount: 6, notEvalCount: 0 },
                  { id: 'iso_27001', name: 'ISO/IEC 27001:2022', version: '2022', avgScore: 86, passCount: 17, failCount: 3, notEvalCount: 0 },
                ]
            ).map((fw) => (
              <div key={fw.id} className="space-y-1.5 p-2.5 rounded-lg bg-slate-950/40 border border-slate-800/80">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-slate-200">{fw.name}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                      {fw.version}
                    </span>
                  </div>
                  <span
                    className={`font-mono font-bold ${
                      fw.avgScore >= 80 ? 'text-emerald-400' : fw.avgScore >= 60 ? 'text-amber-400' : 'text-rose-400'
                    }`}
                  >
                    {fw.avgScore}%
                  </span>
                </div>

                <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      fw.avgScore >= 80
                        ? 'bg-gradient-to-r from-emerald-600 to-teal-400'
                        : fw.avgScore >= 60
                        ? 'bg-gradient-to-r from-amber-600 to-yellow-400'
                        : 'bg-gradient-to-r from-rose-600 to-red-400'
                    }`}
                    style={{ width: `${fw.avgScore}%` }}
                  />
                </div>

                <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-0.5">
                  <span className="text-emerald-400">{fw.passCount} passed</span>
                  <span className="text-rose-400">{fw.failCount} failed</span>
                  <span className="text-slate-500">{fw.notEvalCount} not-eval</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Card 2: Multi-Vendor Fleet Breakdown */}
        <Card
          title="Multi-Vendor Fleet Distribution"
          subtitle="Vendor diversity & average compliance score per NOS"
          action={
            <button
              onClick={() => onNavigateTab('devices')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
            >
              <span>Repository</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          }
        >
          <div className="space-y-4 pt-1">
            {(fleet?.vendorBreakdown && fleet.vendorBreakdown.length > 0
              ? fleet.vendorBreakdown
              : [
                  { vendor: 'Cisco IOS-XE / IOS', count: 1, avgScore: 82, color: '#06b6d4' },
                  { vendor: 'Palo Alto PAN-OS', count: 1, avgScore: 78, color: '#f97316' },
                  { vendor: 'Juniper JunOS', count: 1, avgScore: 85, color: '#a855f7' },
                  { vendor: 'Arista EOS', count: 1, avgScore: 75, color: '#3b82f6' },
                  { vendor: 'SONiC / Linux NOS', count: 1, avgScore: 70, color: '#10b981' },
                ]
            ).map((v) => {
              const vendorTotal = fleet?.totalDevices || totalDevices || 1;
              const pct = Math.round((v.count / vendorTotal) * 100);
              return (
                <div key={v.vendor} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ backgroundColor: v.color || '#38bdf8' }}
                      />
                      <span className="font-medium text-slate-200">{v.vendor}</span>
                    </div>
                    <div className="flex items-center gap-2 font-mono">
                      <span className="text-slate-400">{v.count} device ({pct}%)</span>
                      <span className="text-cyan-400 font-bold">Avg {v.avgScore}%</span>
                    </div>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${v.avgScore}%`,
                        backgroundColor: v.color || '#38bdf8',
                      }}
                    />
                  </div>
                </div>
              );
            })}

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center justify-between text-xs mt-3">
              <span className="text-slate-400">Total Monitored Nodes</span>
              <span className="font-mono font-bold text-slate-200">{totalDevices} Devices</span>
            </div>
          </div>
        </Card>

        {/* Card 3: Top Non-Compliant Security Gaps */}
        <Card
          title="Top Failed Controls & Gaps"
          subtitle="Prioritized for automated vendor CLI remediation"
          action={
            <button
              onClick={() => onNavigateTab('reports')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
            >
              <span>CLI Playbooks</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          }
        >
          <div className="space-y-3 pt-1">
            {(fleet?.topFailedControls && fleet.topFailedControls.length > 0
              ? fleet.topFailedControls
              : [
                  { controlId: 'CIS 1.2', frameworkId: 'cis', title: 'Disable Insecure HTTP Management Service', severity: 'HIGH', failCount: 3 },
                  { controlId: 'NIST SC-13', frameworkId: 'nist_800_53', title: 'Cryptographic Protection - Minimum SSH Key & Cipher Suites', severity: 'HIGH', failCount: 2 },
                  { controlId: 'STIG-NET-000040', frameworkId: 'disa_stig', title: 'Enforce Administrative Idle Session Timeout', severity: 'MEDIUM', failCount: 2 },
                  { controlId: 'ISO A.8.20', frameworkId: 'iso_27001', title: 'Network Security - Centralized Syslog Forwarding', severity: 'MEDIUM', failCount: 2 },
                ]
            ).map((ctrl, i) => (
              <div
                key={i}
                className="p-2.5 rounded-lg bg-slate-950/50 border border-slate-800/80 flex items-start justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-[10px] font-mono font-bold text-cyan-300 bg-cyan-950/60 border border-cyan-500/30 px-1.5 py-0.2 rounded">
                      {ctrl.controlId}
                    </span>
                    <SeverityBadge severity={ctrl.severity as any} size="sm" />
                    <span className="text-[10px] font-mono text-slate-400 uppercase">
                      {ctrl.frameworkId}
                    </span>
                  </div>
                  <p className="text-xs text-slate-200 font-medium mt-1 truncate">
                    {ctrl.title}
                  </p>
                </div>
                <div className="text-right shrink-0">
                  <span className="text-xs font-mono font-bold text-rose-400">
                    {ctrl.failCount} {ctrl.failCount === 1 ? 'device' : 'devices'}
                  </span>
                  <p className="text-[10px] text-slate-500">Failed</p>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Monitored Network Fleet Table */}
      <Card
        title="Fleet Device Inventory & Baseline Posture"
        subtitle="Normalized configuration models with per-device audit scorecards"
        action={
          <button
            onClick={() => onNavigateTab('devices')}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
          >
            <span>Manage All Devices</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                <th className="pb-3 pr-4">Device Hostname</th>
                <th className="pb-3 pr-4">Vendor & NOS</th>
                <th className="pb-3 pr-4">Hardware Model</th>
                <th className="pb-3 pr-4">OS Version</th>
                <th className="pb-3 pr-4">Compliance Score</th>
                <th className="pb-3 pr-4">Parser Coverage</th>
                <th className="pb-3 text-right">Audit Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {devices.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-400">
                    <p className="text-sm font-sans mb-2">No network devices currently registered in repository.</p>
                    <button
                      onClick={handleLoadSamples}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer"
                    >
                      <Database className="w-3.5 h-3.5" />
                      <span>Load Sample Fleet (5 Vendors)</span>
                    </button>
                  </td>
                </tr>
              ) : (
                devices.map((device) => {
                  const score = device.complianceScore ?? device.overallComplianceScore ?? 0;
                  const unrecCount = device.unrecognizedLines?.length ?? 0;
                  const vendor = device.vendor || device.detectedVendor || 'Network Device';
                  return (
                    <tr key={device.id} className="hover:bg-slate-850/50 transition">
                      <td className="py-3 pr-4 font-semibold text-slate-200 flex items-center gap-2">
                        <Cpu className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span>{device.hostname || 'Device'}</span>
                      </td>
                      <td className="py-3 pr-4 font-sans text-slate-300">
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-xs">
                          {vendor}
                        </span>
                      </td>
                      <td className="py-3 pr-4 text-slate-400">
                        {device.model || 'Modular Chassis'}
                      </td>
                      <td className="py-3 pr-4 text-slate-400">
                        {device.osVersion || 'NOS Active'}
                      </td>
                      <td className="py-3 pr-4">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-bold font-mono border ${
                            score >= 80
                              ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40'
                              : score >= 50
                              ? 'bg-amber-950/60 text-amber-300 border-amber-500/40'
                              : 'bg-rose-950/60 text-rose-300 border-rose-500/40'
                          }`}
                        >
                          {score}%
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        {unrecCount === 0 ? (
                          <span className="text-[10px] text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-1.5 py-0.5 rounded">
                            100% Normalized
                          </span>
                        ) : (
                          <span className="text-[10px] text-amber-400 bg-amber-950/40 border border-amber-500/30 px-1.5 py-0.5 rounded">
                            {unrecCount} lines unmapped
                          </span>
                        )}
                      </td>
                      <td className="py-3 text-right">
                        <div className="flex items-center justify-end gap-2 font-sans">
                          <button
                            onClick={() => onNavigateTab('reports')}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition cursor-pointer flex items-center gap-1"
                            title="Generate per-device PDF audit report"
                          >
                            <FileText className="w-3 h-3 text-cyan-400" />
                            <span>Report</span>
                          </button>
                          <button
                            onClick={() => onNavigateTab('compliance')}
                            className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-500/30 text-xs font-medium transition cursor-pointer flex items-center gap-1"
                          >
                            <FileCheck2 className="w-3 h-3 text-cyan-400" />
                            <span>Audit</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Security Audit Ledger Stream */}
      <Card
        title="Tamper-Evident Security Ledger & Normalization Log"
        subtitle="Live cryptographic trail secured with forward-linked SHA-256 block hashes"
        action={
          <button
            onClick={() => onNavigateTab('audit-logs')}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
          >
            <span>Full Ledger</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                <th className="pb-3 pr-4">Timestamp</th>
                <th className="pb-3 pr-4">Target Resource</th>
                <th className="pb-3 pr-4">Security Action</th>
                <th className="pb-3 pr-4">Severity</th>
                <th className="pb-3 pr-4">Operator</th>
                <th className="pb-3 text-right">SHA-256 Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {stats.recentActivities.map((act) => (
                <tr key={act.id} className="hover:bg-slate-850/50 transition">
                  <td className="py-3 pr-4 text-slate-400 whitespace-nowrap">
                    {new Date(act.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3 pr-4 font-sans font-semibold text-slate-200">
                    {act.api}
                  </td>
                  <td className="py-3 pr-4 text-cyan-300 font-sans">
                    {act.event}
                  </td>
                  <td className="py-3 pr-4">
                    <SeverityBadge severity={act.severity as any} size="sm" />
                  </td>
                  <td className="py-3 pr-4 text-slate-400 font-sans">
                    {act.user}
                  </td>
                  <td className="py-3 text-right text-slate-500 text-[10px]">
                    {act.hash}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
