import React, { useState, useEffect } from 'react';
import {
  Server,
  Plus,
  Search,
  Filter,
  Radar,
  Eye,
  Trash2,
  Edit2,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Modal } from '../components/common/Modal';
import { StatusBadge } from '../components/common/Badge';
import { ApiItem } from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';

interface ApiInventoryPageProps {
  onSelectApi: (id: string) => void;
  onScanApi: (id: string) => void;
}

export function ApiInventoryPage({ onSelectApi, onScanApi }: ApiInventoryPageProps) {
  const [apis, setApis] = useState<ApiItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [envFilter, setEnvFilter] = useState('ALL');
  const [authFilter, setAuthFilter] = useState('ALL');

  // Add / Edit Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingApi, setEditingApi] = useState<ApiItem | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    baseUrl: '',
    environment: 'Production' as ApiItem['environment'],
    owner: '',
    authType: 'JWT' as ApiItem['authType'],
    description: '',
  });

  // Delete Confirm Modal State
  const [deletingApi, setDeletingApi] = useState<ApiItem | null>(null);

  const { showToast } = useToast();
  const { hasPermission, role } = useAuth();

  const fetchApis = async () => {
    try {
      setLoading(true);
      const data = await apiService.getApis({
        environment: envFilter,
        authType: authFilter,
        search,
      });
      setApis(data);
    } catch (err: any) {
      showToast('Failed to load APIs', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApis();
  }, [envFilter, authFilter, search]);

  const handleOpenAddModal = () => {
    setEditingApi(null);
    setFormData({
      name: '',
      baseUrl: 'https://api.',
      environment: 'Production',
      owner: '',
      authType: 'JWT',
      description: '',
    });
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (api: ApiItem) => {
    setEditingApi(api);
    setFormData({
      name: api.name,
      baseUrl: api.baseUrl,
      environment: api.environment,
      owner: api.owner,
      authType: api.authType,
      description: api.description,
    });
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim() || !formData.baseUrl.trim() || !formData.owner.trim()) {
      showToast('Validation Error', 'API Name, Base URL, and Owner are required.', 'error');
      return;
    }

    try {
      if (editingApi) {
        await apiService.updateApi(editingApi.id, formData);
        showToast('API Updated', `Configuration updated for ${formData.name}.`, 'success');
      } else {
        await apiService.createApi(formData);
        showToast('API Registered', `New API ${formData.name} added to Zero-Trust inventory.`, 'success');
      }
      setIsModalOpen(false);
      fetchApis();
    } catch (err: any) {
      showToast('Error saving API', err.message, 'error');
    }
  };

  const handleDelete = async () => {
    if (!deletingApi) return;
    try {
      await apiService.deleteApi(deletingApi.id);
      showToast('API Deleted', `Successfully removed ${deletingApi.name}.`, 'success');
      setDeletingApi(null);
      fetchApis();
    } catch (err: any) {
      showToast('Failed to delete API', err.message, 'error');
    }
  };

  return (
    <div className="space-y-6 text-left">
      {/* Header & Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
            API Inventory & Attack Surface
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Cataloged endpoints, authentication topologies, risk postures, and Zero-Trust coverage.
          </p>
        </div>

        {hasPermission('api:create') && (
          <button
            onClick={handleOpenAddModal}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition cursor-pointer self-start sm:self-auto"
          >
            <Plus className="w-4 h-4" />
            <span>Add New API</span>
          </button>
        )}
      </div>

      {/* Filters Bar */}
      <Card className="p-4">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
          {/* Search */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by API name, base URL, or owner..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-lg border border-slate-800 bg-slate-950/80 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Environment Filter */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 shrink-0 font-medium">Environment:</span>
            <select
              value={envFilter}
              onChange={(e) => setEnvFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Environments</option>
              <option value="Production">Production</option>
              <option value="Staging">Staging</option>
              <option value="Development">Development</option>
              <option value="Testing">Testing</option>
            </select>
          </div>

          {/* Auth Filter */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 shrink-0 font-medium">Auth:</span>
            <select
              value={authFilter}
              onChange={(e) => setAuthFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Auth Types</option>
              <option value="JWT">JWT</option>
              <option value="OAuth2">OAuth2</option>
              <option value="API Key">API Key</option>
              <option value="Basic Authentication">Basic Auth</option>
              <option value="None">None (Unauthenticated)</option>
              <option value="Custom">Custom</option>
            </select>
          </div>
        </div>
      </Card>

      {/* API Inventory Table */}
      <Card
        title={`Registered APIs (${apis.length})`}
        subtitle="Monitored targets and runtime posture"
      >
        {loading ? (
          <div className="py-12 text-center text-slate-400 text-xs font-mono">
            Loading API inventory records...
          </div>
        ) : apis.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm">
            No APIs found matching current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="pb-3 pr-4">API Name</th>
                  <th className="pb-3 pr-4">Base URL</th>
                  <th className="pb-3 pr-4">Environment</th>
                  <th className="pb-3 pr-4">Auth Scheme</th>
                  <th className="pb-3 pr-4">Security Score</th>
                  <th className="pb-3 pr-4">Risk Level</th>
                  <th className="pb-3 pr-4">Last Scanned</th>
                  <th className="pb-3 pr-4">Status</th>
                  <th className="pb-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {apis.map((api) => (
                  <tr key={api.id} className="hover:bg-slate-850/50 transition">
                    <td className="py-3.5 pr-4">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-200 text-xs hover:text-cyan-300 cursor-pointer" onClick={() => onSelectApi(api.id)}>
                          {api.name}
                        </span>
                        {api.isDemo && (
                          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-500/30">
                            DEMO
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">Owner: {api.owner}</p>
                    </td>

                    <td className="py-3.5 pr-4 font-mono text-slate-400 text-[11px] max-w-xs truncate">
                      {api.baseUrl}
                    </td>

                    <td className="py-3.5 pr-4">
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          api.environment === 'Production'
                            ? 'bg-rose-950/40 text-rose-300 border-rose-500/30'
                            : api.environment === 'Staging'
                            ? 'bg-amber-950/40 text-amber-300 border-amber-500/30'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                      >
                        {api.environment}
                      </span>
                    </td>

                    <td className="py-3.5 pr-4 font-mono text-cyan-300 text-[11px]">
                      {api.authType}
                    </td>

                    <td className="py-3.5 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              api.securityScore >= 80
                                ? 'bg-emerald-500'
                                : api.securityScore >= 60
                                ? 'bg-amber-500'
                                : 'bg-rose-500'
                            }`}
                            style={{ width: `${api.securityScore}%` }}
                          />
                        </div>
                        <span className="font-mono font-bold text-slate-200 text-xs">
                          {api.securityScore}%
                        </span>
                      </div>
                    </td>

                    <td className="py-3.5 pr-4 font-mono">
                      <span
                        className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                          api.riskScore >= 75
                            ? 'text-rose-400 bg-rose-950/30'
                            : api.riskScore >= 50
                            ? 'text-amber-400 bg-amber-950/30'
                            : 'text-emerald-400 bg-emerald-950/30'
                        }`}
                      >
                        Risk {api.riskScore}
                      </span>
                    </td>

                    <td className="py-3.5 pr-4 text-slate-400 font-mono text-[11px]">
                      {api.lastScan ? (
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3 h-3 text-slate-500" />
                          <span>{new Date(api.lastScan).toLocaleDateString()}</span>
                        </div>
                      ) : (
                        <span className="text-slate-500">Never Scanned</span>
                      )}
                    </td>

                    <td className="py-3.5 pr-4">
                      <StatusBadge status={api.status} size="sm" />
                    </td>

                    <td className="py-3.5 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => onScanApi(api.id)}
                          title="Run Security Scan"
                          className="p-1.5 rounded hover:bg-cyan-950/60 text-cyan-400 hover:text-cyan-300 border border-transparent hover:border-cyan-500/30 transition cursor-pointer"
                        >
                          <Radar className="w-4 h-4" />
                        </button>

                        <button
                          onClick={() => onSelectApi(api.id)}
                          title="View API Details"
                          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
                        >
                          <Eye className="w-4 h-4" />
                        </button>

                        {hasPermission('api:edit') && (
                          <button
                            onClick={() => handleOpenEditModal(api)}
                            title="Edit API"
                            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                        )}

                        {role === 'ADMIN' && (
                          <button
                            onClick={() => setDeletingApi(api)}
                            title="Delete API"
                            className="p-1.5 rounded hover:bg-rose-950/40 text-slate-400 hover:text-rose-400 transition cursor-pointer"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Add / Edit API Modal Form */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title={editingApi ? 'Edit API Configuration' : 'Register New API for Zero-Trust Auditing'}
        subtitle="Define base endpoint and authentication mechanism for security scanning"
        maxWidth="lg"
      >
        <form onSubmit={handleSubmit} className="space-y-4 text-left">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              API Name *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Core Authentication Service"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Base URL *
            </label>
            <input
              type="text"
              required
              placeholder="https://api.internal.corp/v1"
              value={formData.baseUrl}
              onChange={(e) => setFormData({ ...formData, baseUrl: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <p className="text-[10px] text-slate-400 mt-1">
              Note: Zero-Trust policies mandate HTTPS endpoints. Plain HTTP will trigger critical findings.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Environment *
              </label>
              <select
                value={formData.environment}
                onChange={(e) => setFormData({ ...formData, environment: e.target.value as any })}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="Development">Development</option>
                <option value="Testing">Testing</option>
                <option value="Staging">Staging</option>
                <option value="Production">Production</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Authentication Scheme *
              </label>
              <select
                value={formData.authType}
                onChange={(e) => setFormData({ ...formData, authType: e.target.value as any })}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="JWT">JWT (JSON Web Token)</option>
                <option value="OAuth2">OAuth2 / OIDC</option>
                <option value="API Key">API Key</option>
                <option value="Basic Authentication">Basic Authentication</option>
                <option value="None">None (Public / Insecure)</option>
                <option value="Custom">Custom Token Mechanism</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              API Owner / Team *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Identity & Access Management Team"
              value={formData.owner}
              onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              API Description
            </label>
            <textarea
              rows={3}
              placeholder="Provide context regarding business criticality and data sensitivity..."
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsModalOpen(false)}
              className="px-4 py-2 rounded-lg border border-slate-800 text-xs text-slate-400 hover:text-slate-200 transition cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition cursor-pointer"
            >
              {editingApi ? 'Save Changes' : 'Register API'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      {deletingApi && (
        <Modal
          isOpen={true}
          onClose={() => setDeletingApi(null)}
          title="Confirm API Deletion"
          maxWidth="sm"
        >
          <div className="space-y-4 text-left">
            <p className="text-xs text-slate-300">
              Are you sure you want to delete <span className="font-bold text-rose-400">{deletingApi.name}</span>?
              All linked endpoints, findings, and telemetry data will be purged.
            </p>
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setDeletingApi(null)}
                className="px-3 py-1.5 rounded-lg border border-slate-800 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-xs font-semibold text-white"
              >
                Confirm Delete
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
