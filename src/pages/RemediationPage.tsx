import React, { useState, useEffect } from 'react';
import {
  Wrench,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Search,
  Filter,
  ArrowRight,
  FileCode,
  ShieldCheck,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';

export function RemediationPage({ onSelectFinding }: { onSelectFinding: (id: string) => void }) {
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const { showToast } = useToast();

  const fetchItems = async () => {
    try {
      setLoading(true);
      const data = await apiService.getRemediationItems();
      setItems(data);
    } catch (err: any) {
      showToast('Failed to load remediation items', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchItems();
  }, []);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    showToast('Code snippet copied', '', 'info');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredItems = items.filter((item) => {
    const matchesSeverity = severityFilter === 'ALL' || item.severity === severityFilter;
    const matchesSearch =
      item.title.toLowerCase().includes(search.toLowerCase()) ||
      item.apiName.toLowerCase().includes(search.toLowerCase()) ||
      item.findingId.toLowerCase().includes(search.toLowerCase()) ||
      item.endpoint.toLowerCase().includes(search.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  return (
    <div className="space-y-6 text-left">
      {/* Header */}
      <div>
        <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">
          Remediation Guidance & Engineering Playbooks
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
          Actionable fixes, code snippets, and post-deployment validation steps for detected vulnerabilities.
        </p>
      </div>

      {/* Filters Bar */}
      <Card className="p-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative flex-1 w-full sm:w-auto">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search remediation playbooks, findings, endpoints..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <span className="text-xs text-slate-400 shrink-0">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full sm:w-auto px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Remediation Cards */}
      {loading ? (
        <div className="py-12 text-center text-slate-400 text-xs font-mono">
          Loading remediation engine...
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="py-12 text-center text-slate-500 text-sm">
          No open remediation tasks found. All active vulnerabilities resolved!
        </div>
      ) : (
        <div className="space-y-6">
          {filteredItems.map((item) => (
            <Card
              key={item.id}
              title={
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-xs font-bold text-cyan-400">
                    {item.findingId}
                  </span>
                  <span className="font-semibold text-slate-200">{item.title}</span>
                  <span className="text-xs text-slate-400 font-mono hidden md:inline">
                    • {item.apiName} ({item.endpoint})
                  </span>
                </div>
              }
              action={
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={item.severity} size="sm" />
                  <StatusBadge status={item.status} size="sm" />
                  <button
                    onClick={() => onSelectFinding(item.originalFindingId || item.findingId)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-400 hover:text-cyan-300 text-xs font-mono transition cursor-pointer"
                    title="View Full Finding Forensics & Risk Triage"
                  >
                    <ArrowRight className="w-3.5 h-3.5" />
                    <span>Forensics</span>
                  </button>
                </div>
              }
            >
              <div className="space-y-4 text-xs">
                {/* Problem & Why it matters */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="font-mono text-[10px] text-slate-500 uppercase block font-bold">
                      Identified Problem:
                    </span>
                    <p className="text-slate-300 leading-relaxed">{item.problem}</p>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="font-mono text-[10px] text-rose-400 uppercase block font-bold">
                      Why It Matters (Impact):
                    </span>
                    <p className="text-slate-300 leading-relaxed">{item.whyItMatters}</p>
                  </div>
                </div>

                {/* Recommended Fix */}
                <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/30 space-y-1 text-emerald-200">
                  <span className="font-mono text-[10px] text-emerald-400 uppercase block font-bold">
                    Recommended Fix:
                  </span>
                  <p className="leading-relaxed">{item.recommendedFix}</p>
                </div>

                {/* Implementation Guide */}
                <div>
                  <div className="flex items-center justify-between text-slate-400 font-mono mb-1 text-[11px]">
                    <span>Implementation Code / Policy Snippet:</span>
                    <button
                      onClick={() => handleCopy(item.implementationGuide, item.id)}
                      className="text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer"
                    >
                      {copiedId === item.id ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span>Copy Snippet</span>
                    </button>
                  </div>
                  <pre className="p-3.5 rounded-lg bg-black/80 border border-slate-800 font-mono text-xs text-cyan-200 overflow-x-auto select-text whitespace-pre-wrap">
                    {item.implementationGuide}
                  </pre>
                </div>

                {/* Validation Steps */}
                <div>
                  <span className="text-slate-400 font-mono block mb-1 text-[11px]">
                    Validation & Verification Procedure:
                  </span>
                  <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 overflow-x-auto select-text whitespace-pre-wrap">
                    {item.validationSteps}
                  </pre>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
