import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Eye,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ArrowRight,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { SecurityFinding, Severity, FindingStatus } from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';

interface FindingsPageProps {
  onSelectFinding: (id: string) => void;
}

export function FindingsPage({ onSelectFinding }: FindingsPageProps) {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const { showToast } = useToast();

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const data = await apiService.getFindings({
        severity: severityFilter,
        status: statusFilter,
        category: categoryFilter,
        search,
      });
      setFindings(data);
    } catch (err: any) {
      showToast('Error loading findings', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [severityFilter, statusFilter, categoryFilter, search]);

  const categories = [
    'Access Control',
    'Authentication',
    'Rate Limiting',
    'Data Exposure',
    'CORS',
    'Headers',
    'Input Validation',
    'TLS/Crypto',
    'Configuration',
  ];

  return (
    <div className="space-y-6 text-left">
      {/* Header */}
      <div>
        <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
          Security Findings & Vulnerability Registry
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
          Triage, remediate, and track risk status across all cataloged API endpoints.
        </p>
      </div>

      {/* Filters Bar */}
      <Card className="p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search findings, IDs, endpoints..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Severity */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Status */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="RESOLVED">Resolved</option>
            <option value="ACCEPTED_RISK">Accepted Risk</option>
          </select>

          {/* Category */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
      </Card>

      {/* Findings Table */}
      <Card
        title={`Vulnerabilities & Findings (${findings.length})`}
        subtitle="Prioritized list based on CVSS / Zero-Trust impact"
      >
        {loading ? (
          <div className="py-12 text-center text-slate-400 text-xs font-mono">
            Loading security findings...
          </div>
        ) : findings.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm">
            No security findings matching current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="pb-3 pr-4">ID</th>
                  <th className="pb-3 pr-4">Finding Title</th>
                  <th className="pb-3 pr-4">Target API</th>
                  <th className="pb-3 pr-4">Endpoint</th>
                  <th className="pb-3 pr-4">Category</th>
                  <th className="pb-3 pr-4">Severity</th>
                  <th className="pb-3 pr-4">Status</th>
                  <th className="pb-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => onSelectFinding(f.id)}
                    className="hover:bg-slate-850/50 transition cursor-pointer group"
                  >
                    <td className="py-3.5 pr-4 font-mono font-bold text-cyan-400 text-xs whitespace-nowrap">
                      {f.findingId}
                    </td>

                    <td className="py-3.5 pr-4">
                      <p className="font-semibold text-slate-200 group-hover:text-cyan-300 transition">
                        {f.title}
                      </p>
                      <p className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                        {f.description}
                      </p>
                    </td>

                    <td className="py-3.5 pr-4 text-slate-300 whitespace-nowrap">
                      {f.apiName}
                    </td>

                    <td className="py-3.5 pr-4 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                      <span className="text-cyan-300 font-semibold mr-1">{f.method}</span>
                      {f.endpoint}
                    </td>

                    <td className="py-3.5 pr-4 text-slate-400 whitespace-nowrap">
                      {f.category}
                    </td>

                    <td className="py-3.5 pr-4 whitespace-nowrap">
                      <SeverityBadge severity={f.severity} size="sm" />
                    </td>

                    <td className="py-3.5 pr-4 whitespace-nowrap">
                      <StatusBadge status={f.status} size="sm" />
                    </td>

                    <td className="py-3.5 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(f.id);
                        }}
                        className="p-1.5 rounded hover:bg-slate-800 text-slate-400 group-hover:text-cyan-400 transition"
                      >
                        <ArrowRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
