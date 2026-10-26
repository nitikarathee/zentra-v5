import React, { useState, useEffect } from 'react';
import {
  ArrowLeft,
  Server,
  Radar,
  Shield,
  ShieldAlert,
  Clock,
  KeyRound,
  Lock,
  Layers,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Plus,
  Trash2,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Modal } from '../components/common/Modal';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { ApiItem, ApiEndpoint, SecurityFinding, AuditLogEntry } from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';

interface ApiDetailPageProps {
  apiId: string;
  onBack: () => void;
  onScanApi: (id: string) => void;
  onSelectFinding: (id: string) => void;
}

export function ApiDetailPage({ apiId, onBack, onScanApi, onSelectFinding }: ApiDetailPageProps) {
  const [data, setData] = useState<{
    api: ApiItem;
    endpoints: ApiEndpoint[];
    findings: SecurityFinding[];
    activities: AuditLogEntry[];
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'endpoints' | 'findings' | 'auth' | 'logs'>('endpoints');
  const [isAddEndpointModalOpen, setIsAddEndpointModalOpen] = useState(false);
  const [newEpData, setNewEpData] = useState<{
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    path: string;
    authRequired: boolean;
    rateLimitEnabled: boolean;
    sensitivity: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
  }>({
    method: 'GET',
    path: '',
    authRequired: true,
    rateLimitEnabled: true,
    sensitivity: 'INTERNAL',
    riskLevel: 'LOW',
    description: '',
  });

  const { showToast } = useToast();

  const handleAddEndpoint = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newEpData.path.trim()) {
      showToast('Validation Error', 'Endpoint route path is required.', 'error');
      return;
    }
    try {
      const created = await apiService.addEndpoint(apiId, newEpData);
      setData(prev => prev ? { ...prev, endpoints: [...prev.endpoints, created] } : null);
      setIsAddEndpointModalOpen(false);
      setNewEpData({
        method: 'GET',
        path: '',
        authRequired: true,
        rateLimitEnabled: true,
        sensitivity: 'INTERNAL',
        riskLevel: 'LOW',
        description: '',
      });
      showToast('Endpoint Added', `Route ${created.method} ${created.path} registered.`, 'success');
    } catch (err: any) {
      showToast('Failed to add endpoint', err.message, 'error');
    }
  };

  const handleDeleteEndpoint = async (epId: string, epPath: string) => {
    try {
      await apiService.deleteEndpoint(apiId, epId);
      setData(prev => prev ? { ...prev, endpoints: prev.endpoints.filter(e => e.id !== epId) } : null);
      showToast('Endpoint Removed', `Route ${epPath} deleted.`, 'success');
    } catch (err: any) {
      showToast('Failed to delete endpoint', err.message, 'error');
    }
  };

  const fetchDetail = async () => {
    try {
      setLoading(true);
      const res = await apiService.getApi(apiId);
      setData(res);
    } catch (err: any) {
      showToast('Failed to load API details', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetail();
  }, [apiId]);

  if (loading || !data) {
    return (
      <div className="py-20 text-center text-slate-400 text-xs font-mono">
        Loading API deep-dive telemetry...
      </div>
    );
  }

  const { api, endpoints, findings, activities } = data;
  const criticalFindings = findings.filter(f => f.severity === 'CRITICAL' && f.status === 'OPEN').length;
  const highFindings = findings.filter(f => f.severity === 'HIGH' && f.status === 'OPEN').length;

  return (
    <div className="space-y-6 text-left">
      {/* Top Breadcrumb & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl sm:text-2xl font-bold text-slate-100">{api.name}</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {api.environment}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">{api.baseUrl}</p>
          </div>
        </div>

        <button
          onClick={() => onScanApi(api.id)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition cursor-pointer self-start sm:self-auto"
        >
          <Radar className="w-4 h-4" />
          <span>Launch Security Scan</span>
        </button>
      </div>

      {/* Metadata Highlights Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="p-4">
          <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Security Score</p>
          <div className="flex items-center gap-2 mt-1">
            <span className={`text-2xl font-bold font-mono ${api.securityScore >= 80 ? 'text-emerald-400' : 'text-amber-400'}`}>
              {api.securityScore}%
            </span>
            <span className="text-[10px] text-slate-400 font-mono">
              {api.securityScore >= 80 ? 'Compliant' : 'Remediation Needed'}
            </span>
          </div>
        </Card>

        <Card className="p-4">
          <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Risk Score</p>
          <div className="flex items-center gap-2 mt-1">
            <span className={`text-2xl font-bold font-mono ${api.riskScore >= 70 ? 'text-rose-400' : 'text-slate-200'}`}>
              {api.riskScore}
            </span>
            <span className="text-[10px] text-slate-400 font-mono">/ 100 max exposure</span>
          </div>
        </Card>

        <Card className="p-4">
          <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Authentication</p>
          <p className="text-lg font-bold font-mono text-cyan-300 mt-1">{api.authType}</p>
          <p className="text-[10px] text-slate-400">Owner: {api.owner}</p>
        </Card>

        <Card className="p-4">
          <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Active Vulnerabilities</p>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-sm font-mono text-rose-400 font-bold">
              {criticalFindings} Crit
            </span>
            <span className="text-sm font-mono text-amber-400 font-bold">
              {highFindings} High
            </span>
            <span className="text-xs text-slate-400">({findings.length} total)</span>
          </div>
        </Card>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('endpoints')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
            activeTab === 'endpoints'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Endpoints & Routes ({endpoints.length})
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
            activeTab === 'findings'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Security Findings ({findings.length})
        </button>

        <button
          onClick={() => setActiveTab('auth')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
            activeTab === 'auth'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Zero-Trust Auth Topology
        </button>

        <button
          onClick={() => setActiveTab('logs')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
            activeTab === 'logs'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Cryptographic Activity Trail ({activities.length})
        </button>
      </div>

      {/* Tab Contents */}
      {activeTab === 'endpoints' && (
        <Card
          title="Declared API Endpoints"
          subtitle="Mapped route schema, methods, and sensitivity level"
          action={
            <button
              onClick={() => setIsAddEndpointModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Endpoint</span>
            </button>
          }
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="pb-3 pr-4">Method</th>
                  <th className="pb-3 pr-4">Path</th>
                  <th className="pb-3 pr-4">Auth Required</th>
                  <th className="pb-3 pr-4">Rate Limit</th>
                  <th className="pb-3 pr-4">Data Sensitivity</th>
                  <th className="pb-3 pr-4">Risk Level</th>
                  <th className="pb-3 pr-4">Description</th>
                  <th className="pb-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {endpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-slate-850/50">
                    <td className="py-3 pr-4">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          ep.method === 'GET'
                            ? 'bg-blue-950/60 text-blue-400 border border-blue-500/30'
                            : ep.method === 'POST'
                            ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                            : ep.method === 'PUT'
                            ? 'bg-amber-950/60 text-amber-400 border border-amber-500/30'
                            : 'bg-rose-950/60 text-rose-400 border border-rose-500/30'
                        }`}
                      >
                        {ep.method}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-slate-200 font-semibold">{ep.path}</td>
                    <td className="py-3 pr-4">
                      {ep.authRequired ? (
                        <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
                          <CheckCircle2 className="w-3 h-3" /> Enforced
                        </span>
                      ) : (
                        <span className="text-rose-400 flex items-center gap-1 text-[11px]">
                          <AlertTriangle className="w-3 h-3" /> Anonymous
                        </span>
                      )}
                    </td>
                    <td className="py-3 pr-4">
                      <span className={ep.rateLimitEnabled ? 'text-slate-300' : 'text-amber-400'}>
                        {ep.rateLimitEnabled ? '100 req/min' : 'Disabled'}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-slate-400">{ep.sensitivity}</td>
                    <td className="py-3 pr-4">
                      <SeverityBadge severity={ep.riskLevel} size="sm" />
                    </td>
                    <td className="py-3 pr-4 text-slate-400 font-sans text-xs">{ep.description}</td>
                    <td className="py-3 text-right">
                      <button
                        onClick={() => handleDeleteEndpoint(ep.id, ep.path)}
                        title="Delete endpoint"
                        className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-950/30 transition cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {activeTab === 'findings' && (
        <Card title="Discovered Security Findings" subtitle="Vulnerabilities and misconfigurations for this API">
          {findings.length === 0 ? (
            <div className="py-12 text-center text-slate-400 text-xs">
              No findings recorded for this API. Trigger a scan to evaluate posture.
            </div>
          ) : (
            <div className="space-y-3">
              {findings.map((f) => (
                <div
                  key={f.id}
                  onClick={() => onSelectFinding(f.id)}
                  className="p-4 rounded-lg border border-slate-800 bg-slate-950/60 hover:border-slate-700 transition cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-left"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-cyan-400">{f.findingId}</span>
                      <h4 className="text-xs font-semibold text-slate-200 hover:text-cyan-300">
                        {f.title}
                      </h4>
                    </div>
                    <p className="text-xs text-slate-400 line-clamp-1">{f.description}</p>
                    <p className="text-[11px] font-mono text-slate-500">{f.method} {f.endpoint}</p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <SeverityBadge severity={f.severity} size="sm" />
                    <StatusBadge status={f.status} size="sm" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {activeTab === 'auth' && (
        <Card title="Zero-Trust Authentication Details" subtitle="Cryptographic controls and token boundary parameters">
          <div className="space-y-4 text-xs">
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">Current Token Mode:</span>
                <span className="font-mono text-cyan-300 font-bold">{api.authType}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Signature Algorithm:</span>
                <span className="font-mono text-slate-200">ES256 (ECDSA using P-256 and SHA-256)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Token Maximum Lifetime:</span>
                <span className="font-mono text-slate-200">15 minutes (Zero-Trust Standard)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Refresh Token Rotation:</span>
                <span className="text-emerald-400 font-mono">ENABLED (One-time use)</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Mutual TLS (mTLS):</span>
                <span className="text-cyan-400 font-mono">Enforced at API Gateway</span>
              </div>
            </div>
          </div>
        </Card>
      )}

      {activeTab === 'logs' && (
        <Card title="API Activity Ledger" subtitle="Tamper-evident log entries affecting this resource">
          <div className="divide-y divide-slate-800/80">
            {activities.map((log) => (
              <div key={log.id} className="py-3 flex items-start justify-between gap-4 text-xs">
                <div>
                  <div className="flex items-center gap-2 font-mono">
                    <span className="text-cyan-400 font-semibold">{log.action}</span>
                    <span className="text-slate-500">•</span>
                    <span className="text-slate-400">{log.user} ({log.role})</span>
                  </div>
                  <p className="text-slate-300 mt-1">{log.details}</p>
                  <p className="text-[10px] font-mono text-slate-500 mt-0.5">
                    Hash: {log.hash.substring(0, 24)}...
                  </p>
                </div>
                <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Add Endpoint Modal */}
      <Modal
        isOpen={isAddEndpointModalOpen}
        onClose={() => setIsAddEndpointModalOpen(false)}
        title={`Add Endpoint to ${api.name}`}
        subtitle="Declare route schema, authorization perimeter, and data sensitivity tier"
        maxWidth="md"
      >
        <form onSubmit={handleAddEndpoint} className="space-y-4 text-left">
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Method *</label>
              <select
                value={newEpData.method}
                onChange={(e) => setNewEpData({ ...newEpData, method: e.target.value as any })}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>

            <div className="col-span-2">
              <label className="block text-xs font-semibold text-slate-300 mb-1">Path *</label>
              <input
                type="text"
                required
                placeholder="/api/v1/resource"
                value={newEpData.path}
                onChange={(e) => setNewEpData({ ...newEpData, path: e.target.value })}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Sensitivity</label>
              <select
                value={newEpData.sensitivity}
                onChange={(e) => setNewEpData({ ...newEpData, sensitivity: e.target.value as any })}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="PUBLIC">PUBLIC</option>
                <option value="INTERNAL">INTERNAL</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                <option value="RESTRICTED">RESTRICTED</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Risk Level</label>
              <select
                value={newEpData.riskLevel}
                onChange={(e) => setNewEpData({ ...newEpData, riskLevel: e.target.value as any })}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>
          </div>

          <div className="flex items-center gap-6 py-1">
            <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
              <input
                type="checkbox"
                checked={newEpData.authRequired}
                onChange={(e) => setNewEpData({ ...newEpData, authRequired: e.target.checked })}
                className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
              />
              <span>Authentication Enforced</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
              <input
                type="checkbox"
                checked={newEpData.rateLimitEnabled}
                onChange={(e) => setNewEpData({ ...newEpData, rateLimitEnabled: e.target.checked })}
                className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
              />
              <span>Rate Limiting (100 req/min)</span>
            </label>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Description</label>
            <input
              type="text"
              placeholder="Operational purpose or business scope..."
              value={newEpData.description}
              onChange={(e) => setNewEpData({ ...newEpData, description: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsAddEndpointModalOpen(false)}
              className="px-3 py-1.5 rounded-lg border border-slate-800 text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition cursor-pointer"
            >
              Register Endpoint
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
